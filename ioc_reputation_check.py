import requests
import json
import os
from time import sleep

API_KEY = "YOUR_VIRUSTOTAL_API_KEY"  # Buraya kendi Public API anahtarınızı yapıştırın
BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
HEADERS = {"x-apikey": API_KEY}

# Dosya yolları
INPUT_FILE = "ips.txt"
MALICIOUS_FILE = "malicious_ips.txt"
NOT_FOUND_FILE = "not_found_ips.txt"
RESPONSES_DIR = "responses"

# responses klasörünü oluştur
os.makedirs(RESPONSES_DIR, exist_ok=True)

# Boş çıktı dosyaları oluştur
open(MALICIOUS_FILE, 'w').close()
open(NOT_FOUND_FILE, 'w').close()

# IP listesini oku
with open(INPUT_FILE, "r") as f:
    ips = [line.strip() for line in f if line.strip()]

# Her IP için sorgu gönder
for ip in ips:
    url = BASE_URL + ip
    response = requests.get(url, headers=HEADERS)

    if response.status_code == 200:
        data = response.json()

        # JSON cevabını kaydet
        with open(f"{RESPONSES_DIR}/{ip}.json", "w") as f_out:
            json.dump(data, f_out, indent=2)

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            with open(MALICIOUS_FILE, "a") as f:
                f.write(ip + "\n")

    elif response.status_code == 404:
        with open(NOT_FOUND_FILE, "a") as f:
            f.write(ip + "\n")

    else:
        print(f"[!] Hata ({response.status_code}) - IP: {ip}")

    sleep(16)  # Rate limit: 4 istek/dk (VT Public API)
