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
apt-get install -y python3-pip python3-venv git nginx

echo "[2/4] Menyiapkan Virtual Environment Python..."
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

echo "[3/4] Mengkonfigurasi Systemd Service..."
CURRENT_DIR=$(pwd)
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$CURRENT_DIR|g" sismon.service
sed -i "s|Environment=.*|Environment=\"PATH=$CURRENT_DIR/venv/bin\"|g" sismon.service
sed -i "s|ExecStart=.*|ExecStart=$CURRENT_DIR/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 app:app|g" sismon.service

cp sismon.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sismon
systemctl start sismon

echo "[3.5/4] Mengkonfigurasi Nginx Reverse Proxy..."
cp nginx_sismon.conf /etc/nginx/sites-available/sismon
ln -sf /etc/nginx/sites-available/sismon /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx
systemctl enable nginx

echo "[4/4] Setup Selesai!"
echo "==============================================="
echo "Aplikasi sekarang berjalan di background menggunakan Gunicorn."
echo "Website sekarang dapat diakses tanpa port 5000 melalui Nginx."
echo "Untuk mengecek statusnya: systemctl status sismon"
echo "Silakan buka http://vps.homelab.my di browser!"
echo "==============================================="
