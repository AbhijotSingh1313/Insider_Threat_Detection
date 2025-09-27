import sqlite3
import os
from datetime import datetime

def create_database():
    '''Create enhanced security monitoring database with improved schema'''
    try:
        db_path = 'security_monitoring.db'

        # Remove existing database if it exists
        if os.path.exists(db_path):
            os.remove(db_path)
            print("🔄 Removed existing database")

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Enhanced event logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                event_type TEXT,
                description TEXT,
                risk_score REAL DEFAULT 0.0,
                is_suspicious INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                severity_level TEXT DEFAULT 'INFO',
                event_category TEXT,
                user_agent TEXT,
                session_id TEXT,
                geolocation TEXT,
                threat_indicators TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Enhanced FTP logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ftp_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                client_ip TEXT,
                timestamp TEXT NOT NULL,
                action TEXT,
                file_path TEXT,
                risk_score REAL DEFAULT 0.0,
                is_suspicious INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                file_size INTEGER,
                transfer_duration REAL,
                command TEXT,
                response_code INTEGER,
                extra_info TEXT,
                session_duration REAL,
                bytes_transferred INTEGER,
                connection_type TEXT,
                threat_category TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Enhanced suspicious reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                activity_type TEXT,
                source_ip TEXT,
                username TEXT,
                risk_level TEXT,
                details TEXT,
                status TEXT DEFAULT 'new',
                confidence_score REAL DEFAULT 0.0,
                attack_vector TEXT,
                mitigation_suggested TEXT,
                false_positive_likelihood REAL DEFAULT 0.0,
                analyst_notes TEXT,
                escalation_level INTEGER DEFAULT 1,
                evidence_data TEXT,
                related_events TEXT,
                investigation_status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # User behavior analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_behavior (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                behavior_profile TEXT,
                normal_activity_hours TEXT,
                typical_ip_ranges TEXT,
                common_actions TEXT,
                risk_baseline REAL DEFAULT 0.0,
                anomaly_threshold REAL DEFAULT 0.6,
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_events INTEGER DEFAULT 0,
                suspicious_events INTEGER DEFAULT 0,
                behavioral_score REAL DEFAULT 0.0
            )
        ''')

        # IP intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                country_code TEXT,
                is_tor_node INTEGER DEFAULT 0,
                is_vpn INTEGER DEFAULT 0,
                is_proxy INTEGER DEFAULT 0,
                threat_reputation REAL DEFAULT 0.0,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_connections INTEGER DEFAULT 1,
                suspicious_activities INTEGER DEFAULT 0,
                blocked INTEGER DEFAULT 0,
                whitelist INTEGER DEFAULT 0,
                threat_intelligence_source TEXT,
                geolocation TEXT,
                isp TEXT,
                autonomous_system TEXT
            )
        ''')

        # Attack patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name TEXT NOT NULL,
                pattern_type TEXT,
                description TEXT,
                indicators TEXT,
                severity_level TEXT DEFAULT 'MEDIUM',
                confidence_threshold REAL DEFAULT 0.7,
                time_window INTEGER DEFAULT 300,
                event_threshold INTEGER DEFAULT 5,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_triggered DATETIME,
                trigger_count INTEGER DEFAULT 0,
                pattern_active INTEGER DEFAULT 1
            )
        ''')

        # System metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu_percent REAL,
                memory_percent REAL,
                disk_percent REAL,
                network_connections INTEGER,
                active_processes INTEGER,
                system_load REAL,
                threat_level TEXT DEFAULT 'LOW',
                anomalous_activity INTEGER DEFAULT 0
            )
        ''')

        # ML model metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ml_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                model_type TEXT,
                version TEXT,
                training_data_size INTEGER,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_trained DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER DEFAULT 1,
                model_path TEXT,
                hyperparameters TEXT,
                feature_importance TEXT
            )
        ''')

        # Create indexes for better performance
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_event_logs_timestamp ON event_logs(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_event_logs_ip ON event_logs(source_ip)',
            'CREATE INDEX IF NOT EXISTS idx_event_logs_username ON event_logs(username)',
            'CREATE INDEX IF NOT EXISTS idx_event_logs_suspicious ON event_logs(is_suspicious)',
            'CREATE INDEX IF NOT EXISTS idx_ftp_logs_timestamp ON ftp_logs(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_ftp_logs_ip ON ftp_logs(client_ip)',
            'CREATE INDEX IF NOT EXISTS idx_ftp_logs_username ON ftp_logs(username)',
            'CREATE INDEX IF NOT EXISTS idx_ftp_logs_suspicious ON ftp_logs(is_suspicious)',
            'CREATE INDEX IF NOT EXISTS idx_suspicious_reports_timestamp ON suspicious_reports(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_suspicious_reports_status ON suspicious_reports(status)',
            'CREATE INDEX IF NOT EXISTS idx_ip_intelligence_ip ON ip_intelligence(ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_user_behavior_username ON user_behavior(username)'
        ]

        for index_sql in indexes:
            cursor.execute(index_sql)

        # Insert default attack patterns
        default_patterns = [
            ('Brute Force Attack', 'AUTHENTICATION', 'Multiple failed login attempts', 'failed_login,authentication_failure', 'HIGH', 0.8, 300, 5),
            ('Port Scanning', 'RECONNAISSANCE', 'Multiple connection attempts to different ports', 'port_scan,connection_attempts', 'MEDIUM', 0.7, 600, 10),
            ('Data Exfiltration', 'DATA_THEFT', 'Large file downloads or uploads', 'large_transfer,sensitive_files', 'HIGH', 0.75, 900, 3),
            ('Privilege Escalation', 'PRIVILEGE_ABUSE', 'Administrative actions by non-admin users', 'admin_actions,privilege_change', 'HIGH', 0.85, 1800, 2),
            ('After Hours Access', 'SUSPICIOUS_TIMING', 'Access during non-business hours', 'off_hours,unusual_time', 'MEDIUM', 0.6, 3600, 1),
            ('Anonymous Access', 'UNAUTHORIZED_ACCESS', 'Anonymous FTP or guest access', 'anonymous_user,guest_access', 'MEDIUM', 0.65, 300, 1),
            ('Malware Upload', 'MALWARE', 'Upload of executable files', 'executable_upload,malware_signature', 'HIGH', 0.9, 300, 1),
            ('Account Enumeration', 'RECONNAISSANCE', 'Attempts to identify valid user accounts', 'user_enumeration,account_discovery', 'MEDIUM', 0.7, 600, 8)
        ]

        cursor.executemany('''
            INSERT INTO attack_patterns 
            (pattern_name, pattern_type, description, indicators, severity_level, confidence_threshold, time_window, event_threshold)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_patterns)

        # Insert initial ML model metadata
        cursor.execute('''
            INSERT INTO ml_models 
            (model_name, model_type, version, is_active)
            VALUES ('Event Anomaly Detector', 'IsolationForest', '1.0', 1)
        ''')

        cursor.execute('''
            INSERT INTO ml_models 
            (model_name, model_type, version, is_active)
            VALUES ('FTP Behavior Analyzer', 'RandomForest', '1.0', 1)
        ''')

        cursor.execute('''
            INSERT INTO ml_models 
            (model_name, model_type, version, is_active)
            VALUES ('User Behavior Profiler', 'IsolationForest', '1.0', 1)
        ''')

        conn.commit()
        conn.close()

        print("✅ Enhanced security monitoring database created successfully")
        print("📊 Created tables: event_logs, ftp_logs, suspicious_reports, user_behavior,")
        print("   ip_intelligence, attack_patterns, system_metrics, ml_models")
        print("🔍 Added performance indexes and default attack patterns")

        return True

    except Exception as e:
        print(f"❌ Error creating enhanced database: {e}")
        return False

def get_db_connection():
    '''Get database connection with enhanced error handling'''
    try:
        db_path = 'security_monitoring.db'

        if not os.path.exists(db_path):
            print("⚠️ Database not found, creating new one...")
            create_database()

        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row  # Enable dict-like access

        # Enable WAL mode for better concurrent access
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA cache_size=10000')
        conn.execute('PRAGMA temp_store=MEMORY')

        return conn

    except sqlite3.Error as e:
        print(f"❌ Database connection error: {e}")
        return None
    except Exception as e:
        print(f"❌ Unexpected database error: {e}")
        return None

def verify_database_integrity():
    '''Verify database integrity and structure'''
    try:
        conn = get_db_connection()
        if not conn:
            return False

        # Check if all required tables exist
        required_tables = [
            'event_logs', 'ftp_logs', 'suspicious_reports', 'user_behavior',
            'ip_intelligence', 'attack_patterns', 'system_metrics', 'ml_models'
        ]

        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in cursor.fetchall()]

        missing_tables = set(required_tables) - set(existing_tables)

        if missing_tables:
            print(f"⚠️ Missing tables: {missing_tables}")
            print("🔧 Recreating database...")
            conn.close()
            create_database()
            return True

        # Run integrity check
        cursor.execute("PRAGMA integrity_check")
        integrity_result = cursor.fetchone()[0]

        if integrity_result != 'ok':
            print(f"❌ Database integrity check failed: {integrity_result}")
            conn.close()
            return False

        conn.close()
        print("✅ Database integrity verified")
        return True

    except Exception as e:
        print(f"❌ Error verifying database: {e}")
        return False

def get_database_stats():
    '''Get database statistics'''
    try:
        conn = get_db_connection()
        if not conn:
            return {}

        stats = {}

        # Get table row counts
        tables = ['event_logs', 'ftp_logs', 'suspicious_reports', 'user_behavior', 'ip_intelligence']

        for table in tables:
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            stats[f"{table}_count"] = cursor.fetchone()[0]

        # Get database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        stats['database_size_bytes'] = cursor.fetchone()[0]

        # Get recent activity
        cursor.execute("SELECT COUNT(*) FROM event_logs WHERE datetime(timestamp) >= datetime('now', '-24 hours')")
        stats['events_last_24h'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ftp_logs WHERE datetime(timestamp) >= datetime('now', '-24 hours')")
        stats['ftp_activity_last_24h'] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM suspicious_reports WHERE status = 'new'")
        stats['pending_reports'] = cursor.fetchone()[0]

        conn.close()
        return stats

    except Exception as e:
        print(f"❌ Error getting database stats: {e}")
        return {}

def cleanup_old_data(days_to_keep=30):
    '''Clean up old data to maintain database performance'''
    try:
        conn = get_db_connection()
        if not conn:
            return False

        cutoff_date = f"datetime('now', '-{days_to_keep} days')"

        # Clean old event logs
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM event_logs WHERE datetime(timestamp) < {cutoff_date}")
        deleted_events = cursor.rowcount

        cursor.execute(f"DELETE FROM ftp_logs WHERE datetime(timestamp) < {cutoff_date}")
        deleted_ftp = cursor.rowcount

        cursor.execute(f"DELETE FROM system_metrics WHERE datetime(timestamp) < {cutoff_date}")
        deleted_metrics = cursor.rowcount

        # Update IP intelligence last seen dates
        cursor.execute(f"UPDATE ip_intelligence SET last_seen = last_seen WHERE last_seen >= {cutoff_date}")

        # Vacuum database to reclaim space
        cursor.execute("VACUUM")

        conn.commit()
        conn.close()

        print(f"🧹 Cleanup completed:")
        print(f"   Deleted {deleted_events} old event logs")
        print(f"   Deleted {deleted_ftp} old FTP logs") 
        print(f"   Deleted {deleted_metrics} old system metrics")
        print(f"   Database optimized")

        return True

    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        return False

if __name__ == '__main__':
    print("🗄️ Enhanced Database Initialization")
    print("=" * 50)

    # Create database
    if create_database():
        print()

        # Verify integrity
        if verify_database_integrity():
            print()

            # Show statistics
            stats = get_database_stats()
            if stats:
                print("📈 Database Statistics:")
                for key, value in stats.items():
                    print(f"   {key}: {value}")
                print()

            print("✅ Enhanced database setup completed successfully")
        else:
            print("❌ Database verification failed")
    else:
        print("❌ Database creation failed")
