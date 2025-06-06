# 🛡️ IOC Reputation Checker (VirusTotal API)

This Python script checks the reputation of IP addresses using the **VirusTotal Public API**. It identifies malicious or suspicious IPs from a list and logs the results accordingly.

---

## 📂 Features

- Reads IPs from a text file (`ips.txt`)
- Sends reputation queries to VirusTotal
- Saves full JSON responses in the `responses/` directory
- Generates:
  - `malicious_ips.txt` → IPs flagged as malicious or suspicious
  - `not_found_ips.txt` → IPs not found in VirusTotal’s database

---

## 🚀 Requirements

- Python 3.x
- `requests` library

Install the required library with:

```bash
pip install requests
```

---

## 🔧 Usage

1. Create a file named `ips.txt` in the same directory, with one IP per line:
```
8.8.8.8
1.1.1.1
```

2. Open the script and replace the placeholder with your actual [VirusTotal Public API Key](https://www.virustotal.com/gui/my-apikey):
```python
API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
```

3. Run the script:
```bash
python3 ioc_reputation_check.py
```

4. After execution, check the following files:
- `malicious_ips.txt` → Contains flagged IPs
- `not_found_ips.txt` → Contains IPs with no VirusTotal data
- `responses/` → Contains raw JSON API responses

---

## 🕐 Rate Limiting Notice

This script respects the **VirusTotal Public API limit** of **4 requests per minute** by pausing for 16 seconds between each request. Do not remove the `sleep(16)` line unless using the Premium API.

---

## ⚠️ Disclaimer

This tool is intended for **educational and cybersecurity research purposes only**. Use responsibly and in compliance with [VirusTotal’s Terms of Service](https://support.virustotal.com/hc/en-us/articles/115002146809-Terms-of-Service).
