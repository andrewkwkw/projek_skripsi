import os
import time
import subprocess
import threading
import json
import psutil
from flask import Flask, render_template, jsonify, Response
from model import SSHLogAnalyzer
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = Flask(__name__)

# ==========================================
# GLOBAL STATE & CONFIGURATION
# ==========================================
MODEL_FILE = "model.pkl"
GLOBAL_ANALYZER = None
ROLLING_LOGS = []
MAX_ROLLING_LINES = 1000

# Cache for latest results to serve to non-SSE clients if needed
LATEST_ANALYSIS = {}
LATEST_LIVELOG = {}

# List of active SSE client queues
SSE_CLIENTS = []

def get_log_file():
    if os.path.exists("/var/log/auth.log"):
        return "/var/log/auth.log"
    if os.path.exists("auth2.log"):
        return "auth2.log"
    if os.path.exists("../auth2.log"):
        return "../auth2.log"
    return "auth2.log"

def get_tail_lines(filepath, n_lines):
    if os.name == 'posix':
        try:
            result = subprocess.run(['tail', '-n', str(n_lines), filepath], stdout=subprocess.PIPE, text=True, errors='ignore')
            return result.stdout.splitlines(keepends=True)
        except Exception:
            pass
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()[-n_lines:]
    except Exception:
        return []

# ==========================================
# CORE PROCESSING LOGIC
# ==========================================
def process_logs_batch(raw_lines):
    """Memproses raw_lines menggunakan pre-trained model dan mengupdate state"""
    global GLOBAL_ANALYZER, LATEST_ANALYSIS, LATEST_LIVELOG
    
    if not GLOBAL_ANALYZER or not raw_lines:
        return

    start_time = time.time()
    
    df_parsed = GLOBAL_ANALYZER.parse_log(raw_lines)
    df_features = GLOBAL_ANALYZER.feature_engineering(df_parsed)
    results = GLOBAL_ANALYZER.detect_anomalies(df_features)
    
    # Aggregasi berdasarkan IP
    aggregated = {}
    for r in results:
        ip = r['ip']
        failed_count = int(r['failed_count'])
        if_label = int(r['if_label'])
        z_score = float(r['z_score'])
        severity = r['severity']
        
        reasons = []
        if z_score > 3: reasons.append("Z-Score Tinggi")
        if if_label == -1: reasons.append("Deteksi Anomali")
        reason = " & ".join(reasons) if reasons else "Normal"

        if ip not in aggregated:
            aggregated[ip] = {
                'ip': ip,
                'time_window': r['time_window'],
                'failed_count': failed_count,
                'z_score': z_score,
                'if_label': if_label,
                'severity': severity,
                'reason': reason,
                'top_username': r['top_username']
            }
        else:
            # Akumulasi count
            aggregated[ip]['failed_count'] += failed_count
            # Ambil Z-score tertinggi
            if z_score > aggregated[ip]['z_score']:
                aggregated[ip]['z_score'] = z_score
                aggregated[ip]['reason'] = reason # Update reason mengikuti z_score tertinggi
            # Ambil Severity terburuk
            if severity == 'CRITICAL':
                aggregated[ip]['severity'] = 'CRITICAL'
            elif severity == 'WARNING' and aggregated[ip]['severity'] != 'CRITICAL':
                aggregated[ip]['severity'] = 'WARNING'
            # Ambil label IF terburuk (-1)
            if if_label == -1:
                aggregated[ip]['if_label'] = -1
                
    results_sorted = sorted(list(aggregated.values()), key=lambda x: x['failed_count'], reverse=True)
    
    summary = {
        "critical": sum(1 for r in results_sorted if r['severity'] == 'CRITICAL'),
        "warning": sum(1 for r in results_sorted if r['severity'] == 'WARNING'),
        "normal": sum(1 for r in results_sorted if r['severity'] == 'NORMAL'),
        "total_ips": len(results_sorted)
    }
    
    trend_zscore_labels = [f"{r['ip']} ({r['time_window']})" for r in results_sorted[:15]]
    trend_zscore_data = [r['failed_count'] for r in results_sorted[:15]]
    trend_anomaly_data = [r['z_score'] for r in results_sorted[:15]]
    trend_if_data = [r['if_label'] for r in results_sorted[:15]]
    
    peak_zscore = results_sorted[0]['ip'] if results_sorted else "-"
    
    if_counts = {}
    user_counts = {}
    for r in results_sorted:
        if r['if_label'] == -1:
            if_counts[r['ip']] = if_counts.get(r['ip'], 0) + 1
        if r['top_username'] != "-":
            user_counts[r['top_username']] = user_counts.get(r['top_username'], 0) + r['failed_count']
            
    peak_if = max(if_counts.items(), key=lambda x: x[1])[0] if if_counts else "-"
    top_users_list = [{"username": k, "count": v} for k, v in sorted(user_counts.items(), key=lambda x: x[1], reverse=True)]
    peak_user = top_users_list[0]['username'] if top_users_list else "-"

    inference_time = (time.time() - start_time) * 1000 # ms

    LATEST_ANALYSIS = {
        "summary": summary,
        "peak_zscore_ip": peak_zscore,
        "peak_if_ip": peak_if,
        "peak_user": peak_user,
        "top_users": top_users_list,
        "logs": results_sorted,
        "chart_labels": trend_zscore_labels,
        "chart_failed": trend_zscore_data,
        "chart_zscore": trend_anomaly_data,
        "chart_if": trend_if_data,
        "inference_latency_ms": round(inference_time, 2)
    }

    # Process Livelog
    df_success = df_parsed[df_parsed['status'] == 'success'].tail(100)
    df_failed = df_parsed[df_parsed['status'] == 'failed'].tail(100)
    
    success_logs = []
    if not df_success.empty:
        success_logs = df_success.apply(lambda row: f"{row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - {row['ip']} ({row['username']})", axis=1).tolist()
        
    failed_logs = []
    if not df_failed.empty:
        failed_logs = df_failed.apply(lambda row: f"{row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - {row['ip']} ({row['username']})", axis=1).tolist()
    
    LATEST_LIVELOG = {
        "success_logs": success_logs[::-1],
        "failed_logs": failed_logs[::-1],
        "raw_logs": raw_lines[::-1][:200]
    }
    
    # Broadcast to SSE Clients
    notify_sse_clients()

def notify_sse_clients():
    payload = {
        "analysis": LATEST_ANALYSIS,
        "livelog": LATEST_LIVELOG
    }
    data = f"data: {json.dumps(payload)}\n\n"
    for queue in SSE_CLIENTS:
        queue.append(data)

# ==========================================
# WATCHDOG & INITIALIZATION
# ==========================================
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, filepath):
        self.filepath = filepath
        self.file_pointer = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        self.debounce_timer = None

    def on_modified(self, event):
        if event.src_path == os.path.abspath(self.filepath):
            if self.debounce_timer is not None:
                self.debounce_timer.cancel()
            self.debounce_timer = threading.Timer(1.0, self.read_new_lines)
            self.debounce_timer.start()

    def read_new_lines(self):
        global ROLLING_LOGS
        try:
            if os.path.getsize(self.filepath) < self.file_pointer:
                self.file_pointer = 0 # File rotated
                
            with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(self.file_pointer)
                new_lines = f.readlines()
                self.file_pointer = f.tell()
                
            if new_lines:
                ROLLING_LOGS.extend(new_lines)
                if len(ROLLING_LOGS) > MAX_ROLLING_LINES:
                    del ROLLING_LOGS[:-MAX_ROLLING_LINES]
                process_logs_batch(ROLLING_LOGS)
        except Exception as e:
            print("Error membaca log baru:", e)

def init_system():
    global GLOBAL_ANALYZER, ROLLING_LOGS
    
    # 1. Autonomous Training / Model Loading
    if os.path.exists(MODEL_FILE):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Memuat Pre-Trained Model dari {MODEL_FILE}...")
        GLOBAL_ANALYZER = SSHLogAnalyzer.load_model(MODEL_FILE)
    else:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Model belum ada. Memulai Autonomous Training (10,000 data)...")
        log_file = get_log_file()
        raw_logs = get_tail_lines(log_file, 10000)
        GLOBAL_ANALYZER = SSHLogAnalyzer(contamination='auto')
        df_parsed = GLOBAL_ANALYZER.parse_log(raw_logs)
        df_features = GLOBAL_ANALYZER.feature_engineering(df_parsed)
        GLOBAL_ANALYZER.train_isolation_forest(df_features)
        GLOBAL_ANALYZER.save_model(MODEL_FILE)
        print("✅ Autonomous Training Selesai.")

    # 2. Inisialisasi Rolling Data
    log_file = get_log_file()
    ROLLING_LOGS = get_tail_lines(log_file, MAX_ROLLING_LINES)
    process_logs_batch(ROLLING_LOGS)

    # 3. Mulai Watchdog Observer
    if os.path.exists(log_file):
        observer = Observer()
        event_handler = LogFileHandler(log_file)
        observer.schedule(event_handler, path=os.path.dirname(os.path.abspath(log_file)), recursive=False)
        observer.start()
        print(f"👀 Watchdog aktif memantau file: {log_file}")
        # Note: We don't join the observer so it runs in background

# ==========================================
# FLASK ROUTES
# ==========================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stream')
def api_stream():
    def event_stream():
        q = []
        SSE_CLIENTS.append(q)
        try:
            # Kirim data awal saat pertama konek
            payload = {"analysis": LATEST_ANALYSIS, "livelog": LATEST_LIVELOG}
            yield f"data: {json.dumps(payload)}\n\n"
            
            # Terus tunggu data baru
            while True:
                if q:
                    yield q.pop(0)
                else:
                    time.sleep(0.5)
        except GeneratorExit:
            SSE_CLIENTS.remove(q)
            
    return Response(event_stream(), mimetype="text/event-stream")



# Untuk Backward Compatibility jika ada yang masih hit API biasa
@app.route('/api/analyze')
def api_analyze():
    return jsonify(LATEST_ANALYSIS)

@app.route('/api/livelog')
def api_livelog():
    return jsonify(LATEST_LIVELOG)

# ==========================================
# STARTUP
# ==========================================
from datetime import datetime
init_system()

if __name__ == '__main__':
    # Disable reloader to prevent running watchdog and initialization twice
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
