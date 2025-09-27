import sqlite3
from datetime import datetime

def force_flag_suspicious():
    """Force flag existing data as suspicious to create reports"""

    print("🚨 Force flagging data as suspicious...")

    try:
        conn = sqlite3.connect('security_monitoring.db')
        cursor = conn.cursor()

        # Check existing data
        cursor.execute("SELECT COUNT(*) FROM event_logs")
        total_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ftp_logs")
        total_ftp = cursor.fetchone()[0]

        print(f"Found {total_events} total events")
        print(f"Found {total_ftp} total FTP logs")

        if total_events == 0 and total_ftp == 0:
            print("❌ No data found! Start monitoring first")
            return

        # Flag failed logins as suspicious
        cursor.execute("""
            UPDATE event_logs 
            SET is_suspicious = 1, risk_score = 0.8, processed = 1
            WHERE (event_id = 4625 OR event_type LIKE '%Failed%' OR event_type LIKE '%failed%')
            AND is_suspicious = 0
        """)
        failed_logins = cursor.rowcount

        # Flag after-hours activity
        cursor.execute("""
            UPDATE event_logs 
            SET is_suspicious = 1, risk_score = 0.6, processed = 1
            WHERE (cast(strftime('%H', timestamp) as integer) >= 22 
                   OR cast(strftime('%H', timestamp) as integer) <= 6)
            AND is_suspicious = 0
        """)
        after_hours = cursor.rowcount

        # Flag admin/root access
        cursor.execute("""
            UPDATE event_logs 
            SET is_suspicious = 1, risk_score = 0.7, processed = 1
            WHERE username IN ('admin', 'administrator', 'root', 'system')
            AND is_suspicious = 0
        """)
        admin_access = cursor.rowcount

        # Flag FTP failed logins
        cursor.execute("""
            UPDATE ftp_logs 
            SET is_suspicious = 1, risk_score = 0.8, processed = 1
            WHERE action LIKE '%failed%' 
            AND is_suspicious = 0
        """)
        ftp_failed = cursor.rowcount

        # Flag anonymous FTP
        cursor.execute("""
            UPDATE ftp_logs 
            SET is_suspicious = 1, risk_score = 0.6, processed = 1
            WHERE username IN ('anonymous', 'ftp', 'guest')
            AND is_suspicious = 0
        """)
        anonymous_ftp = cursor.rowcount

        # Flag any remaining events with some risk
        cursor.execute("""
            UPDATE event_logs 
            SET is_suspicious = 1, risk_score = 0.5, processed = 1
            WHERE is_suspicious = 0 
            LIMIT 10
        """)
        random_events = cursor.rowcount

        conn.commit()
        conn.close()

        total_flagged = failed_logins + after_hours + admin_access + ftp_failed + anonymous_ftp + random_events

        print(f"✅ Flagged {failed_logins} failed login events")
        print(f"✅ Flagged {after_hours} after-hours events")
        print(f"✅ Flagged {admin_access} admin access events")
        print(f"✅ Flagged {ftp_failed} FTP failed logins")
        print(f"✅ Flagged {anonymous_ftp} anonymous FTP accesses")
        print(f"✅ Flagged {random_events} random events")
        print(f"\n🎉 Total flagged: {total_flagged} suspicious activities")

        if total_flagged > 0:
            print("Now run the report creator script!")
        else:
            print("No activities were flagged - check your data")

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == '__main__':
    force_flag_suspicious()
