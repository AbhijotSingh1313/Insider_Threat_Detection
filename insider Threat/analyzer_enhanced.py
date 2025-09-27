import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
import joblib
import os
from datetime import datetime, timedelta
import json
from db_init_enhanced import get_db_connection
import logging
import warnings
warnings.filterwarnings('ignore')

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class RealWorldThreatDetector:
    """Real-world ML threat detection based on actual data patterns - NO SYNTHETIC DATA"""

    def __init__(self):
        self.event_model = None
        self.ftp_model = None
        self.behavioral_model = None
        self.event_scaler = None
        self.ftp_scaler = None
        self.behavioral_scaler = None
        self.feature_encoders = {}
        self.model_trained = False

        # Real threat intelligence from actual security research
        self.known_attack_signatures = {
            'failed_login_thresholds': {
                'single_user_failures': 5,      # 5+ failures from one user
                'single_ip_failures': 10,       # 10+ failures from one IP
                'time_window_minutes': 15       # Within 15 minutes
            },
            'privilege_escalation_indicators': {
                'admin_accounts': ['admin', 'administrator', 'root', 'system', 'sa'],
                'service_accounts': ['service', 'svc', 'system', 'local'],
                'critical_events': [4672, 4673, 4732, 4728],  # Windows privilege events
                'suspicious_commands': ['net user', 'net group', 'runas', 'whoami /priv']
            },
            'data_exfiltration_patterns': {
                'file_extensions': ['.zip', '.rar', '.7z', '.tar', '.gz', '.backup'],
                'sensitive_keywords': ['password', 'credential', 'secret', 'key', 'token'],
                'large_transfer_threshold': 100 * 1024 * 1024,  # 100MB
                'bulk_operation_threshold': 50  # 50+ files
            },
            'temporal_anomalies': {
                'after_hours': [(22, 23), (0, 6)],  # 10PM-11PM, Midnight-6AM
                'weekend_risk_multiplier': 1.5,
                'holiday_risk_multiplier': 2.0
            },
            'network_indicators': {
                'internal_ranges': ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', 
                                   '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                                   '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
                                   '127.0.0.', '169.254.'],
                'suspicious_countries': ['CN', 'RU', 'KP', 'IR', 'SY'],
                'tor_exit_nodes': [],  # Would be populated from threat intelligence feeds
                'known_bad_ips': []    # Would be populated from threat intelligence feeds
            }
        }

        # Real behavioral analysis patterns
        self.behavioral_baselines = {
            'normal_work_hours': (8, 18),
            'typical_session_duration_minutes': (30, 480),  # 30 mins to 8 hours
            'normal_file_access_rate': 50,  # files per hour
            'normal_login_locations': 3,    # max different IPs per user per day
            'normal_failure_rate': 0.05     # 5% login failure rate is normal
        }

        # Model persistence
        self.model_dir = 'ml_models'
        os.makedirs(self.model_dir, exist_ok=True)

        # Statistical analysis storage
        self.user_profiles = {}
        self.ip_profiles = {}
        self.system_baseline = None

        logger.info("Real-world threat detector initialized - data-driven analysis only")
        self.load_existing_models()

    def load_existing_models(self):
        """Load any existing trained models"""
        try:
            model_files = {
                'event_model': os.path.join(self.model_dir, 'event_anomaly_model.pkl'),
                'ftp_model': os.path.join(self.model_dir, 'ftp_anomaly_model.pkl'),
                'behavioral_model': os.path.join(self.model_dir, 'behavioral_model.pkl'),
                'scalers': os.path.join(self.model_dir, 'feature_scalers.pkl'),
                'encoders': os.path.join(self.model_dir, 'feature_encoders.pkl'),
                'profiles': os.path.join(self.model_dir, 'user_profiles.pkl')
            }

            all_exist = all(os.path.exists(path) for path in model_files.values())

            if all_exist:
                self.event_model = joblib.load(model_files['event_model'])
                self.ftp_model = joblib.load(model_files['ftp_model'])
                self.behavioral_model = joblib.load(model_files['behavioral_model'])

                scalers = joblib.load(model_files['scalers'])
                self.event_scaler = scalers.get('event_scaler')
                self.ftp_scaler = scalers.get('ftp_scaler')
                self.behavioral_scaler = scalers.get('behavioral_scaler')

                self.feature_encoders = joblib.load(model_files['encoders'])

                profiles = joblib.load(model_files['profiles'])
                self.user_profiles = profiles.get('user_profiles', {})
                self.ip_profiles = profiles.get('ip_profiles', {})
                self.system_baseline = profiles.get('system_baseline', None)

                self.model_trained = True
                logger.info("✅ Pre-trained models loaded successfully")
            else:
                logger.info("⚠️ No pre-trained models found. Will train on actual data.")

        except Exception as e:
            logger.warning(f"⚠️ Error loading models: {e}")
            self.model_trained = False

    def train_models_on_real_data(self, min_samples_required=100):
        """Train ML models using ONLY real data from database"""
        try:
            conn = get_db_connection()
            if not conn:
                logger.error("❌ Cannot connect to database")
                return False

            logger.info("📊 Training models on real data from database...")

            # Load real data from database
            event_query = """SELECT * FROM event_logs 
                           WHERE timestamp >= datetime('now', '-30 days')
                           ORDER BY timestamp DESC"""
            event_data = pd.read_sql_query(event_query, conn)

            ftp_query = """SELECT * FROM ftp_logs 
                         WHERE timestamp >= datetime('now', '-30 days')
                         ORDER BY timestamp DESC"""
            ftp_data = pd.read_sql_query(ftp_query, conn)
            conn.close()

            logger.info(f"📈 Loaded {len(event_data)} event logs and {len(ftp_data)} FTP logs")

            # Check if we have enough data for meaningful training
            if len(event_data) < min_samples_required and len(ftp_data) < min_samples_required:
                logger.warning(f"⚠️ Insufficient real data for training (need {min_samples_required}+ samples)")
                logger.info("🎯 System will use rule-based analysis until more data is collected")
                return False

            # Train models on real data
            models_trained = 0

            # Train event model if we have enough event data
            if len(event_data) >= min_samples_required:
                if self._train_event_anomaly_detector(event_data):
                    models_trained += 1
                    logger.info("✅ Event anomaly detector trained on real data")

            # Train FTP model if we have enough FTP data
            if len(ftp_data) >= min_samples_required:
                if self._train_ftp_anomaly_detector(ftp_data):
                    models_trained += 1
                    logger.info("✅ FTP anomaly detector trained on real data")

            # Train behavioral model if we have enough combined data
            if len(event_data) + len(ftp_data) >= min_samples_required:
                if self._train_behavioral_analyzer(event_data, ftp_data):
                    models_trained += 1
                    logger.info("✅ Behavioral analyzer trained on real data")

            # Build user and system profiles
            self._build_user_profiles(event_data, ftp_data)
            self._build_system_baseline(event_data, ftp_data)

            if models_trained > 0:
                self.model_trained = True
                self.save_models()
                logger.info(f"✅ {models_trained} ML models trained successfully on real data")
                return True
            else:
                logger.warning("⚠️ No models could be trained - insufficient data")
                return False

        except Exception as e:
            logger.error(f"❌ Error training models: {e}")
            return False

    def analyze_events(self, events):
        """Analyze events using real data-driven models or intelligent rules"""
        try:
            if not events:
                return []

            df = pd.DataFrame([dict(event) for event in events])

            # Use real models if available, otherwise intelligent rule-based analysis
            if self.model_trained and self.event_model:
                return self._ml_based_event_analysis(df)
            else:
                return self._intelligent_rule_based_analysis(df, 'events')

        except Exception as e:
            logger.error(f"❌ Error analyzing events: {e}")
            return [(row.get('id', i), False, 0.3) for i, row in enumerate(events)]

    def analyze_ftp_logs(self, logs):
        """Analyze FTP logs using real data-driven models or intelligent rules"""
        try:
            if not logs:
                return []

            df = pd.DataFrame([dict(log) for log in logs])

            if self.model_trained and self.ftp_model:
                return self._ml_based_ftp_analysis(df)
            else:
                return self._intelligent_rule_based_analysis(df, 'ftp')

        except Exception as e:
            logger.error(f"❌ Error analyzing FTP logs: {e}")
            return [(row.get('id', i), False, 0.2) for i, row in enumerate(logs)]

    def _intelligent_rule_based_analysis(self, df, data_type):
        """Enhanced rule-based analysis using threat intelligence and user profiles"""
        results = []

        for i, (_, row) in enumerate(df.iterrows()):
            row_id = row.get('id', i)
            base_risk = row.get('risk_score', 0.3 if data_type == 'events' else 0.2)

            # Apply threat intelligence rules
            risk_adjustments = []

            # Time-based analysis
            try:
                timestamp = pd.to_datetime(row.get('timestamp'))
                hour = timestamp.hour

                # After hours detection
                if hour >= 22 or hour <= 6:
                    risk_adjustments.append(('after_hours', 0.3))

                # Weekend activity
                if timestamp.weekday() >= 5:
                    risk_adjustments.append(('weekend', 0.2))

            except:
                pass

            # User-based analysis
            username = row.get('username', '')
            if username in self.user_profiles:
                profile = self.user_profiles[username]

                # Compare against user's normal behavior
                try:
                    if hour not in profile.get('typical_hours', []):
                        risk_adjustments.append(('unusual_hour_for_user', 0.2))
                    if timestamp.weekday() not in profile.get('typical_days', []):
                        risk_adjustments.append(('unusual_day_for_user', 0.15))
                except:
                    pass

                # Check failure rate
                if profile['failure_rate'] > self.behavioral_baselines['normal_failure_rate']:
                    risk_adjustments.append(('high_failure_user', 0.25))

            # Privilege escalation detection
            admin_indicators = self.known_attack_signatures['privilege_escalation_indicators']['admin_accounts']
            if any(indicator.lower() in username.lower() for indicator in admin_indicators):
                risk_adjustments.append(('privileged_account', 0.3))

            # IP-based analysis
            ip_field = 'source_ip' if data_type == 'events' else 'client_ip'
            ip_address = row.get(ip_field, '')

            if ip_address:
                # External IP detection
                is_internal = any(ip_address.startswith(prefix) for prefix in 
                                self.known_attack_signatures['network_indicators']['internal_ranges'])
                if not is_internal:
                    risk_adjustments.append(('external_ip', 0.4))

                # Check against user's common IPs
                if username in self.user_profiles:
                    common_ips = self.user_profiles[username].get('common_ips', [])
                    if ip_address not in common_ips:
                        risk_adjustments.append(('new_ip_for_user', 0.2))

            # Event-specific analysis
            if data_type == 'events':
                event_id = row.get('event_id', 0)
                critical_events = self.known_attack_signatures['privilege_escalation_indicators']['critical_events']

                if event_id == 4625:  # Failed logon
                    risk_adjustments.append(('failed_login_attempt', 0.5))
                elif event_id == 1102:  # Audit log cleared
                    risk_adjustments.append(('audit_tampering', 0.8))
                elif event_id in critical_events:
                    risk_adjustments.append(('privilege_event', 0.4))

            elif data_type == 'ftp':
                action = row.get('action', '')
                file_path = row.get('file_path', '')

                if action == 'failed_login':
                    risk_adjustments.append(('ftp_failed_login', 0.6))
                elif action in ['upload', 'download']:
                    risk_adjustments.append(('file_transfer', 0.2))

                # File analysis
                if file_path:
                    suspicious_extensions = self.known_attack_signatures['data_exfiltration_patterns']['file_extensions']
                    if any(ext in file_path.lower() for ext in suspicious_extensions):
                        risk_adjustments.append(('suspicious_file_type', 0.4))

                    sensitive_keywords = self.known_attack_signatures['data_exfiltration_patterns']['sensitive_keywords']
                    if any(keyword in file_path.lower() for keyword in sensitive_keywords):
                        risk_adjustments.append(('sensitive_file', 0.5))

            # Calculate final risk score
            total_adjustment = sum(adjustment for _, adjustment in risk_adjustments)
            final_risk = min(1.0, base_risk + total_adjustment)

            # Determine if suspicious
            is_suspicious = final_risk >= 0.6 or len([adj for adj in risk_adjustments if adj[1] >= 0.4]) >= 2

            results.append((row_id, is_suspicious, final_risk))

        return results

    def _build_user_profiles(self, event_data, ftp_data):
        """Build statistical profiles for each user based on real activity"""
        try:
            # Get unique users
            event_users = set(event_data['username'].dropna().unique()) if 'username' in event_data.columns else set()
            ftp_users = set(ftp_data['username'].dropna().unique()) if 'username' in ftp_data.columns else set()
            all_users = event_users.union(ftp_users)

            for username in all_users:
                if pd.isna(username) or username in ['unknown', '', 'NaN']:
                    continue

                user_events = event_data[event_data['username'] == username] if 'username' in event_data.columns else pd.DataFrame()
                user_ftp = ftp_data[ftp_data['username'] == username] if 'username' in ftp_data.columns else pd.DataFrame()

                if len(user_events) == 0 and len(user_ftp) == 0:
                    continue

                profile = {
                    'first_seen': None,
                    'last_seen': None,
                    'total_events': len(user_events),
                    'total_ftp_actions': len(user_ftp),
                    'typical_hours': [],
                    'typical_days': [],
                    'common_ips': [],
                    'failure_rate': 0.0,
                    'avg_risk_score': 0.0
                }

                # Temporal patterns
                all_timestamps = []
                if len(user_events) > 0:
                    user_events['timestamp'] = pd.to_datetime(user_events['timestamp'])
                    all_timestamps.extend(user_events['timestamp'].tolist())

                if len(user_ftp) > 0:
                    user_ftp['timestamp'] = pd.to_datetime(user_ftp['timestamp'])
                    all_timestamps.extend(user_ftp['timestamp'].tolist())

                if all_timestamps:
                    all_timestamps = pd.to_datetime(all_timestamps)
                    profile['first_seen'] = all_timestamps.min().strftime('%Y-%m-%d %H:%M:%S')
                    profile['last_seen'] = all_timestamps.max().strftime('%Y-%m-%d %H:%M:%S')
                    profile['typical_hours'] = all_timestamps.hour.value_counts().head(5).index.tolist()
                    profile['typical_days'] = all_timestamps.dayofweek.value_counts().head(5).index.tolist()

                # IP patterns
                all_ips = []
                if len(user_events) > 0 and 'source_ip' in user_events.columns:
                    all_ips.extend(user_events['source_ip'].dropna().tolist())
                if len(user_ftp) > 0 and 'client_ip' in user_ftp.columns:
                    all_ips.extend(user_ftp['client_ip'].dropna().tolist())

                if all_ips:
                    ip_counts = pd.Series(all_ips).value_counts()
                    profile['common_ips'] = ip_counts.head(5).index.tolist()

                # Calculate failure rates and risk scores
                total_attempts = len(user_events) + len(user_ftp)
                failures = 0

                if len(user_events) > 0:
                    failures += len(user_events[user_events['event_id'] == 4625]) if 'event_id' in user_events.columns else 0
                if len(user_ftp) > 0:
                    failures += len(user_ftp[user_ftp['action'] == 'failed_login']) if 'action' in user_ftp.columns else 0

                profile['failure_rate'] = failures / max(1, total_attempts)

                # Average risk scores
                risk_scores = []
                if len(user_events) > 0 and 'risk_score' in user_events.columns:
                    risk_scores.extend(user_events['risk_score'].dropna().tolist())
                if len(user_ftp) > 0 and 'risk_score' in user_ftp.columns:
                    risk_scores.extend(user_ftp['risk_score'].dropna().tolist())

                profile['avg_risk_score'] = np.mean(risk_scores) if risk_scores else 0.0

                self.user_profiles[username] = profile

            logger.info(f"📊 Built profiles for {len(self.user_profiles)} users")

        except Exception as e:
            logger.error(f"❌ Error building user profiles: {e}")

    def _build_system_baseline(self, event_data, ftp_data):
        """Build system-wide baseline metrics from real data"""
        try:
            baseline = {
                'total_events': len(event_data),
                'total_ftp_logs': len(ftp_data),
                'data_collection_period_days': 0,
                'average_events_per_hour': 0,
                'average_ftp_per_hour': 0,
                'peak_hours': [],
                'common_event_types': [],
                'common_ftp_actions': [],
                'baseline_risk_score': 0.0,
                'failure_baseline': 0.0
            }

            # Calculate time span
            all_timestamps = []
            if len(event_data) > 0:
                event_data['timestamp'] = pd.to_datetime(event_data['timestamp'])
                all_timestamps.extend(event_data['timestamp'].tolist())
            if len(ftp_data) > 0:
                ftp_data['timestamp'] = pd.to_datetime(ftp_data['timestamp'])
                all_timestamps.extend(ftp_data['timestamp'].tolist())

            if all_timestamps:
                all_timestamps = pd.to_datetime(all_timestamps)
                time_span = (all_timestamps.max() - all_timestamps.min()).total_seconds() / 86400  # days
                baseline['data_collection_period_days'] = max(1, time_span)

                # Calculate averages
                baseline['average_events_per_hour'] = len(event_data) / max(1, time_span * 24)
                baseline['average_ftp_per_hour'] = len(ftp_data) / max(1, time_span * 24)

                # Peak hours
                baseline['peak_hours'] = all_timestamps.hour.value_counts().head(5).index.tolist()

            # Common patterns
            if len(event_data) > 0 and 'event_type' in event_data.columns:
                baseline['common_event_types'] = event_data['event_type'].value_counts().head(10).index.tolist()

            if len(ftp_data) > 0 and 'action' in ftp_data.columns:
                baseline['common_ftp_actions'] = ftp_data['action'].value_counts().head(10).index.tolist()

            # Risk baselines
            all_risk_scores = []
            if len(event_data) > 0 and 'risk_score' in event_data.columns:
                all_risk_scores.extend(event_data['risk_score'].dropna().tolist())
            if len(ftp_data) > 0 and 'risk_score' in ftp_data.columns:
                all_risk_scores.extend(ftp_data['risk_score'].dropna().tolist())

            baseline['baseline_risk_score'] = np.mean(all_risk_scores) if all_risk_scores else 0.0

            # Failure rate baseline
            total_activities = len(event_data) + len(ftp_data)
            total_failures = 0
            if len(event_data) > 0 and 'event_id' in event_data.columns:
                total_failures += len(event_data[event_data['event_id'] == 4625])
            if len(ftp_data) > 0 and 'action' in ftp_data.columns:
                total_failures += len(ftp_data[ftp_data['action'] == 'failed_login'])

            baseline['failure_baseline'] = total_failures / max(1, total_activities)

            self.system_baseline = baseline
            logger.info(f"📊 System baseline established over {baseline['data_collection_period_days']:.1f} days")

        except Exception as e:
            logger.error(f"❌ Error building system baseline: {e}")

    def save_models(self):
        """Save trained models and profiles"""
        try:
            model_files = {
                'event_model': os.path.join(self.model_dir, 'event_anomaly_model.pkl'),
                'ftp_model': os.path.join(self.model_dir, 'ftp_anomaly_model.pkl'),
                'behavioral_model': os.path.join(self.model_dir, 'behavioral_model.pkl'),
                'scalers': os.path.join(self.model_dir, 'feature_scalers.pkl'),
                'encoders': os.path.join(self.model_dir, 'feature_encoders.pkl'),
                'profiles': os.path.join(self.model_dir, 'user_profiles.pkl')
            }

            # Save models
            if self.event_model:
                joblib.dump(self.event_model, model_files['event_model'])
            if self.ftp_model:
                joblib.dump(self.ftp_model, model_files['ftp_model'])
            if self.behavioral_model:
                joblib.dump(self.behavioral_model, model_files['behavioral_model'])

            # Save scalers
            scalers = {
                'event_scaler': self.event_scaler,
                'ftp_scaler': self.ftp_scaler,
                'behavioral_scaler': self.behavioral_scaler
            }
            joblib.dump(scalers, model_files['scalers'])

            # Save encoders
            joblib.dump(self.feature_encoders, model_files['encoders'])

            # Save profiles
            profiles = {
                'user_profiles': self.user_profiles,
                'ip_profiles': self.ip_profiles,
                'system_baseline': self.system_baseline
            }
            joblib.dump(profiles, model_files['profiles'])

            logger.info("💾 Models and profiles saved successfully")

        except Exception as e:
            logger.error(f"❌ Error saving models: {e}")

    def train_models(self, force_retrain=False):
        """Public interface for training models"""
        return self.train_models_on_real_data(min_samples_required=50 if force_retrain else 100)

    def get_model_status(self):
        """Get comprehensive model and analysis status"""
        return {
            'models_trained': self.model_trained,
            'models_available': {
                'event_model': self.event_model is not None,
                'ftp_model': self.ftp_model is not None,
                'behavioral_model': self.behavioral_model is not None
            },
            'profiles_built': {
                'user_profiles': len(self.user_profiles),
                'system_baseline': self.system_baseline is not None
            },
            'analysis_mode': 'ML-based' if self.model_trained else 'Rule-based with threat intelligence',
            'data_sources': 'Real database logs only - no synthetic data'
        }


# Alias for backward compatibility
SuspiciousActivityDetector = RealWorldThreatDetector


if __name__ == '__main__':
    logger.info("🧪 Testing Real-World Threat Detector...")
    detector = RealWorldThreatDetector()

    # Test with real data
    success = detector.train_models_on_real_data(min_samples_required=10)  # Lower threshold for testing

    if success:
        logger.info("✅ Models trained on real data")
    else:
        logger.info("ℹ️ Using intelligent rule-based analysis")

    status = detector.get_model_status()
    logger.info(f"📊 Detector Status: {status}")
    logger.info("✅ Real-world threat detector test completed")
