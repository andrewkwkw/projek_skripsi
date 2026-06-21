import os
import sys
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# Mengimpor class SSHLogAnalyzer dari model.py yang ada di dalam folder VPS
from model import SSHLogAnalyzer

def run_eval(analyzer, name, raw_logs):
    print(f"\n==================================================")
    print(f"      EVALUASI {name}")
    print(f"==================================================")
    df_parsed = analyzer.parse_log(raw_logs)
    df_features = analyzer.feature_engineering(df_parsed)
    
    if df_features.empty:
        print("Tidak ada data yang bisa dievaluasi.")
        return

    # Evaluasi menggunakan model yang ada
    print("Memuat 'otak' model (model.pkl) untuk mengevaluasi data terbaru...")
    try:
        analyzer = SSHLogAnalyzer.load_model("model.pkl")
    except Exception as e:
        print(f"Gagal memuat model.pkl: {e}")
        return
        
    results = analyzer.detect_anomalies(df_features)

    y_true = []
    y_pred = []
    
    for res in results:
        # Ground truth asumsi: gagal >= 5 adalah serangan
        if res['failed_count'] >= 5:
            y_true.append(1)
        else:
            y_true.append(0)
            
        # Prediksi model
        if res['severity'] in ['WARNING', 'CRITICAL']:
            y_pred.append(1)
        else:
            y_pred.append(0)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    print(f"Total Data (Jendela Waktu) : {len(y_true)}")
    print("-" * 50)
    print(f"Accuracy  : {accuracy * 100:>6.2f}% (Ketepatan tebakan keseluruhan)")
    print(f"Precision : {precision * 100:>6.2f}% (Berapa persen alarm yang BENAR)")
    print(f"Recall    : {recall * 100:>6.2f}% (Berapa persen serangan TERTANGKAP)")
    print(f"F1-Score  : {f1 * 100:>6.2f}% (Keseimbangan Precision & Recall)")
    print("-" * 50)
    
    print("\n[ Confusion Matrix ]")
    print("                     | Prediksi Aman(0) | Prediksi Serangan(1)")
    if cm.shape == (2, 2):
        print(f"Aslinya Aman (0)     | {cm[0][0]:<16} | {cm[0][1]}")
        print(f"Aslinya Serangan (1) | {cm[1][0]:<16} | {cm[1][1]}")
            
        print("\n[ Rincian Kasus ]")
        print(f"- True Negative (Aman & Ditebak Aman)               : {cm[0][0]}")
        print(f"- False Positive (Alarm Palsu/Halu)                 : {cm[0][1]}")
        print(f"- False Negative (Kebobolan / Tidak Terdeteksi)     : {cm[1][0]}")
        print(f"- True Positive (Serangan Berhasil Tertangkap)      : {cm[1][1]}")
    else:
        print("Data terlalu sedikit atau tidak ada variasi serangan untuk membuat Matrix penuh.")
    print("="*50)

    # === TAMBAHKAN KODE INI UNTUK MENYIMPAN GAMBAR ===
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Aman (0)', 'Serangan (1)'], 
                yticklabels=['Aman (0)', 'Serangan (1)'])
    plt.title(f"Confusion Matrix - {name}")
    plt.ylabel('Aktual')
    plt.xlabel('Prediksi')
    plt.tight_layout()
    plt.savefig('confusion_matrix.png')
    plt.close()
    print(">>> Gambar Confusion Matrix berhasil disimpan sebagai 'confusion_matrix.png'")
    # =================================================


def evaluate_model():
    log_file = "/var/log/auth.log"
    
    # Cek apakah dijalankan di OS Windows (berarti uji coba lokal)
    if os.name == 'nt':
        print("Tampaknya Anda menjalankan ini di Windows/Lokal.")
        print("Skrip ini dikhususkan untuk berjalan di Linux VPS (/var/log/auth.log).")
        sys.exit(1)

    if not os.path.exists(log_file):
        print(f"File {log_file} tidak ditemukan di VPS ini!")
        sys.exit(1)

    print(f"Membaca file log produksi VPS: {log_file}...")
    
    # Membaca log dengan batasan memori (membaca 100.000 baris terakhir saja agar VPS tidak hang)
    MAX_LINES = 100000
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        # Membaca semua baris
        all_logs = f.readlines()
        
        # Mengambil baris terbaru saja jika terlalu besar
        if len(all_logs) > MAX_LINES:
            print(f"Log terlalu besar ({len(all_logs)} baris). Mengambil {MAX_LINES} baris terbaru saja untuk mencegah server hang...")
            raw_logs = all_logs[-MAX_LINES:]
        else:
            raw_logs = all_logs

    # Evaluasi Model Utama (Tuning Optimal)
    analyzer = SSHLogAnalyzer(contamination=0.35, n_estimators=300)
    run_eval(analyzer, "MODEL SISMON (DATA LIVE VPS)", raw_logs)

if __name__ == "__main__":
    evaluate_model()
