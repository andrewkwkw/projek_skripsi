import pandas as pd
import numpy as np
import re
import os
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class SSHLogAnalyzer:
    def __init__(self, contamination='auto'):
        # Regex dasar
        self.regex_pattern = re.compile(
            r'(?P<date>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})))\s+\S+\s+sshd\[\d+\]:\s*'
            r'(?P<message>.*)'
        )
        self.ip_pattern = re.compile(r'(?:rhost=|from\s+)(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        self.user_pattern = re.compile(r'(?:user=|user\s+|for\s+)(?P<user>\S+)')
        
        # Inisialisasi
        self.iso_forest = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        
        # Data statistik simulasi untuk Z-Score (Akan ditimpa saat training)
        self.history_mean_failed = 2.0
        self.history_std_failed = 1.0
        self.is_fitted = False

    def parse_log(self, raw_logs):
        parsed_data = []
        for line in raw_logs:
            match = self.regex_pattern.search(line)
            if not match: continue
            
            date_str = match.group('date')
            message = match.group('message').lower()
            
            ip_match = self.ip_pattern.search(message)
            ip = ip_match.group('ip') if ip_match else None
            
            user_match = self.user_pattern.search(message)
            user = user_match.group('user') if user_match else 'unknown'
            
            status = 'unknown'
            if 'failure' in message or 'failed' in message:
                status = 'failed'
            elif 'invalid user' in message or 'user unknown' in message:
                status = 'invalid'
            elif 'accepted' in message:
                status = 'success'
                
            if ip and status in ['failed', 'invalid', 'success']:
                # Konversi string ke object Datetime
                try:
                    if date_str[0].isdigit():
                        # Ambil 19 karakter pertama (YYYY-MM-DDTHH:MM:SS) untuk menghindari pergeseran Timezone UTC
                        dt_obj = pd.to_datetime(date_str[:19])
                    else:
                        dt_obj = pd.to_datetime(f"{date_str} {datetime.now().year}")
                except Exception:
                    dt_obj = pd.NaT
                parsed_data.append({'timestamp': dt_obj, 'ip': ip, 'username': user, 'status': status})
        
        if not parsed_data:
            return pd.DataFrame(columns=['timestamp', 'ip', 'username', 'status'])
            
        return pd.DataFrame(parsed_data)

    def feature_engineering(self, df):
        if df.empty: return pd.DataFrame()
        features = []
        
        # Hapus baris yang gagal di-parse waktunya
        df = df.dropna(subset=['timestamp'])
        
        # Mengelompokkan berdasarkan IP dan Jendela Waktu (misal per 1 Menit)
        for (ip, time_window), group in df.groupby(['ip', pd.Grouper(key='timestamp', freq='1min')]):
            total_attempts = len(group)
            if total_attempts == 0:
                continue
                
            failed_count = len(group[group['status'] == 'failed']) + len(group[group['status'] == 'invalid'])
            unique_user_count = group['username'].nunique()
            invalid_count = len(group[group['status'] == 'invalid'])
            
            invalid_user_ratio = invalid_count / total_attempts if total_attempts > 0 else 0
            
            # Cari username yang paling sering dicoba di window ini
            top_username = group['username'].value_counts().idxmax() if not group.empty else "-"
            
            features.append({
                'time_window': time_window.strftime('%d %b %Y, %H:%M'),
                'ip': ip,
                'failed_count': failed_count,
                'unique_user_count': unique_user_count,
                'invalid_user_ratio': invalid_user_ratio,
                'top_username': top_username
            })
        return pd.DataFrame(features)

    def train_isolation_forest(self, train_df_features):
        if train_df_features.empty: return
        
        # Penetapan Baseline Normal sesuai dengan Proposal Skripsi
        self.history_mean_failed = 5.0
        self.history_std_failed = 2.0
            
        X = train_df_features[['failed_count', 'unique_user_count', 'invalid_user_ratio']]
        X_scaled = self.scaler.fit_transform(X)
        self.iso_forest.fit(X_scaled)
        self.is_fitted = True

    def calculate_z_score(self, failed_count):
        if self.history_std_failed == 0: return 0
        return (failed_count - self.history_mean_failed) / self.history_std_failed

    def detect_anomalies(self, df_features):
        if df_features.empty or not self.is_fitted: return []
        X = df_features[['failed_count', 'unique_user_count', 'invalid_user_ratio']]
        
        # Scaling
        X_scaled = self.scaler.transform(X)
        
        # Prediction (-1: anomaly, 1: normal)
        preds = self.iso_forest.predict(X_scaled)
        
        results = []
        for i, row in df_features.iterrows():
            z_score = self.calculate_z_score(row['failed_count'])
            severity = 'NORMAL'
            if preds[i] == -1 or z_score > 3:
                severity = 'WARNING'
                if preds[i] == -1 and z_score > 3:
                    severity = 'CRITICAL'
                    
            results.append({
                'time_window': row['time_window'],
                'ip': row['ip'],
                'failed_count': row['failed_count'],
                'unique_user_count': row['unique_user_count'],
                'invalid_user_ratio': row['invalid_user_ratio'],
                'top_username': row.get('top_username', '-'),
                'if_label': preds[i],
                'z_score': round(z_score, 2),
                'severity': severity
            })
        return results
        
    def save_model(self, filepath):
        if self.is_fitted:
            model_data = {
                'iso_forest': self.iso_forest,
                'scaler': self.scaler,
                'mean': self.history_mean_failed,
                'std': self.history_std_failed
            }
            joblib.dump(model_data, filepath)
            print(f"Model berhasil disimpan ke {filepath}")
        else:
            print("Model belum dilatih, tidak dapat menyimpan!")
            
    @classmethod
    def load_model(cls, filepath):
        if os.path.exists(filepath):
            model_data = joblib.load(filepath)
            instance = cls()
            if isinstance(model_data, dict):
                instance.iso_forest = model_data.get('iso_forest')
                instance.scaler = model_data.get('scaler')
                instance.history_mean_failed = model_data.get('mean', 2.0)
                instance.history_std_failed = model_data.get('std', 1.0)
            else:
                instance.iso_forest = model_data
                instance.scaler = StandardScaler() # Fallback if it was just the forest
            instance.is_fitted = True
            print(f"Model berhasil dimuat dari {filepath}")
            return instance
        else:
            raise FileNotFoundError(f"File model {filepath} tidak ditemukan!")

if __name__ == "__main__":
    import sys
    log_file = "auth.log"
    if not os.path.exists(log_file):
        print(f"File {log_file} tidak ditemukan!")
        sys.exit(1)

    with open(log_file, "r") as f:
        raw_logs = f.readlines()

    # Kita menggunakan contamination 0.2 untuk contoh data yang sangat kecil
    analyzer = SSHLogAnalyzer(contamination=0.2)
    
    print("=== TAHAP 2: PARSING LOG ===")
    df_parsed = analyzer.parse_log(raw_logs)
    print(df_parsed.to_string())
    print("\n")
    
    print("=== TAHAP 3: FEATURE ENGINEERING (SAMPEL) ===")
    df_features = analyzer.feature_engineering(df_parsed)
    print(df_features.head(10).to_string())
    print("... (data selanjutnya disembunyikan agar rapi) ...\n")
    
    print("=== TRAINING ISOLATION FOREST ===")
    analyzer.train_isolation_forest(df_features)
    print("Model berhasil dilatih.\n")
    
    print("=== TAHAP 4 & 5: DETEKSI ANCAMAN (HANYA MENAMPILKAN ANOMALI) ===")
    results = analyzer.detect_anomalies(df_features)
    
    anomalies_found = False
    for res in results:
        if res['severity'] in ['WARNING', 'CRITICAL']:
            anomalies_found = True
            print(f"[{res['time_window']}] IP: {res['ip']:<15} | Failed: {res['failed_count']:<3} | "
                  f"Z-Score: {res['z_score']:>5.2f} | IF Output: {res['if_label']:>2} | "
                  f"SEVERITY: {res['severity']}")
                  
    if not anomalies_found:
        print("✅ Server Aman. Tidak ada serangan brute-force yang terdeteksi.")

