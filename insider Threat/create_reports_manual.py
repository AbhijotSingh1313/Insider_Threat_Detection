import sqlite3
from datetime import datetime

def create_reports_from_suspicious_data():
    """Create reports from all existing suspicious activities"""

    print("Creating reports from suspicious data...")

    try:
        conn = sqlite3.connect('security_monitoring.db')
        cursor = conn.cursor()

        # Check what we have
        cursor.execute("SELECT COUNT(*) FROM event_logs WHERE is_suspicious = 1")
        sus_events = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM ftp_logs WHERE is_suspicious = 1") 
        sus_ftp = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM suspicious_reports")
        existing_reports = cursor.fetchone()[0]

        print(f"Found {sus_events} suspicious events")
        print(f"Found {sus_ftp} suspicious FTP logs")
        print(f"Found {existing_reports} existing reports")

        if sus_events == 0 and sus_ftp == 0:
            print("No suspicious data found!")
            print("First run your monitoring or flag data as suspicious")
            return

        reports_created = 0

        # Create reports for suspicious events
        cursor.execute("SELECT * FROM event_logs WHERE is_suspicious = 1")
        for event in cursor.fetchall():
            try:
                activity_type = f"Suspicious Event: {event[5]}"  # event_type
                source_ip = event[3] or "Unknown"  # source_ip
                username = event[4] or "Unknown"  # username
                details = f"Event ID: {event[1]}, Description: {event[6]}"  # event_id, description
                risk_level = 'HIGH' if event[7] >= 0.8 else 'MEDIUM'  # risk_score

                # Check if report already exists
                cursor.execute("""
                    SELECT COUNT(*) FROM suspicious_reports 
                    WHERE username = ? AND activity_type = ? AND date(timestamp) = date(?)
                """, (username, activity_type, event[2]))

                if cursor.fetchone()[0] == 0:
                    cursor.execute("""
                        INSERT INTO suspicious_reports 
                        (timestamp, activity_type, source_ip, username, risk_level, details, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'new')
                    """, (event[2], activity_type, source_ip, username, risk_level, details))
                    reports_created += 1
                    print(f"Created report for {username}: {activity_type}")

            except Exception as e:
                print(f"Error creating event report: {e}")

        # Create reports for suspicious FTP logs  
        cursor.execute("SELECT * FROM ftp_logs WHERE is_suspicious = 1")
        for ftp_log in cursor.fetchall():
            try:
                activity_type = f"Suspicious FTP: {ftp_log[4]}"  # action
                source_ip = ftp_log[2] or "Unknown"  # client_ip
                username = ftp_log[1] or "Unknown"  # username
                details = f"File: {ftp_log[5] or 'N/A'}, Action: {ftp_log[4]}"  # file_path, action
                risk_level = 'HIGH' if ftp_log[7] >= 0.8 else 'MEDIUM'  # risk_score

                cursor.execute("""
                    SELECT COUNT(*) FROM suspicious_reports 
                    WHERE username = ? AND activity_type = ? AND date(timestamp) = date(?)
                """, (username, activity_type, ftp_log[3]))

                if cursor.fetchone()[0] == 0:
                    cursor.execute("""
                        INSERT INTO suspicious_reports 
                        (timestamp, activity_type, source_ip, username, risk_level, details, status)
                        VALUES (?, ?, ?, ?, ?, ?, 'new')
                    """, (ftp_log[3], activity_type, source_ip, username, risk_level, details))
                    reports_created += 1
                    print(f"Created report for {username}: {activity_type}")

            except Exception as e:
                print(f"Error creating FTP report: {e}")

        conn.commit()
        conn.close()

        print(f"\nCreated {reports_created} new reports!")
        if reports_created > 0:
            print("Go to http://localhost:5000/reports to see them!")
        else:
            print("No new reports needed - all suspicious activities already have reports")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    create_reports_from_suspicious_data()
