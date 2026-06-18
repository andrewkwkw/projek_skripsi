#!/bin/bash
echo "==============================================="
echo " SETUP SISTEM MONITORING SSH (SKRIPSI 178)"
echo "==============================================="

# Pastikan script dijalankan sebagai root
if [ "$EUID" -ne 0 ]
  then echo "Harap jalankan script ini sebagai root (sudo ./setup_vps.sh)"
  exit
fi

echo "[1/4] Menginstall dependencies OS..."
apt-get update
apt-get install -y python3-pip python3-venv git

echo "[2/4] Menyiapkan Virtual Environment Python..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "[3/4] Mengkonfigurasi Systemd Service..."
CURRENT_DIR=$(pwd)
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$CURRENT_DIR|g" sismon.service
sed -i "s|Environment=.*|Environment=\"PATH=$CURRENT_DIR/venv/bin\"|g" sismon.service
sed -i "s|ExecStart=.*|ExecStart=$CURRENT_DIR/venv/bin/gunicorn --workers 1 --threads 4 --bind 0.0.0.0:80 app:app|g" sismon.service

cp sismon.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sismon
systemctl start sismon

echo "[4/4] Setup Selesai!"
echo "==============================================="
echo "Aplikasi sekarang berjalan di background menggunakan Gunicorn."
echo "Untuk mengecek statusnya: systemctl status sismon"
echo "Silakan buka http://[IP_VPS_ANDA] di browser!"
echo "==============================================="
