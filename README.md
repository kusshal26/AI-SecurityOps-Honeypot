# 🧠 AI SecurityOps Honeypot

A lightweight, **AI-assisted honeypot** built for learning and security research.  
It monitors attacker behavior, tags commands by severity, and displays them in a clean SOC-style dashboard.

---

## ⚠️ Before You Start

Please read this carefully --- **running a honeypot carries real risks**.

1. 🖥️ **Use a virtual machine.**  
   Always run this project inside a **VM (VirtualBox, VMware, etc.)** that's isolated from your main computer.

2. 🌐 **Do not expose it publicly** unless you understand the risks.  
   Keep the honeypot bound to `127.0.0.1` or your LAN for testing.  

3. 🔑 **Change the secrets.**  
   - Edit `dashboard.py` → set your own `APP.secret_key`.  
   - Update the login credentials (default: `admin` / `1234`).  

4. 🧩 **Assume logs may contain malicious data.**  
   Don't open random files under `sessions_fs/` or `transcripts/` on your host.

5. 🧯 **You are responsible for your deployment.**  
   Use this project for **educational and defensive** purposes only.

---

## 🧱 Project Structure

main.py             → Honeypot server (TCP listener + command logger)
dashboard.py        → Flask web UI (dark mode dashboard)
mock_ai_api.py      → Local AI mock analyzer (can be replaced later)
utils.py            → Helper functions & analyzer logic
db.py               → SQLite schema and DB helpers
alerts.py           → Optional alerting hooks
test_client.py      → Simple attacker simulation client
simulate_attacks.py → Fake event injector (for demo data)
start_honeypot.bat  → Quick launcher for Windows
hp_events.db        → Database (auto-created)
transcripts/        → Session command logs
sessions_fs/        → Simulated file systems per session
geoip_cache.json    → Cached IP → Country/ASN map
requirements.txt

---

## 🧩 Requirements

- **Windows 10 or plus**
- **Python 3.9+** (make sure it's added to PATH)
- Internet connection (for GeoIP lookups)

Install dependencies
Using CMD:
```
python -m pip install -r requirements.txt
```

## 🚀 Running the Honeypot (Auto-Setup)

Open the project folder double-click on "start_honeypot.bat" Quick launcher 

## 🚀 Running the Honeypot (Manual Setup)

Open **three PowerShell windows** in the project folder side by side.

### 1️⃣ Start the AI analyzer
Powershell 1 run:
```
python mock_ai_api.py
```

You should see:
```
 * Running on http://127.0.0.1:9000
```


---

### 2️⃣ Start the honeypot server
Powershell 2 run:
```
python main.py
```

Expected output:
```
[*] Honeypot bound to port 2229
[+] Honeypot active on 0.0.0.0:2229. Waiting for connections...
```


If port 2229 is already used, the honeypot will automatically try 2230 or higher.

---

### 3️⃣ Start the dashboard
Powershell 3 run:
```
python dashboard.py
```

Then open your browser and visit:  
```
👉 http://127.0.0.1:8080
```

Default login credentials(*You change it in dashboard.py*):
```
Username: admin
Password: 1234
```


---

## 🧪 Testing the Honeypot

You can test using the included **test client**:

Open PowerShell in the project folder and run:
```
python test_client.py
```


You'll see logs like:
```
[LOG] 127.0.0.1:55010 | LOW | ls
[LOG] 127.0.0.1:55010 | HIGH | sudo apt update
[LOG] 127.0.0.1:55010 | CRITICAL | rm -rf /
```
Refresh your dashboard - the events will appear instantly.

---

## 🧰 Optional: Simulate Realistic Attacks

To quickly fill your dashboard with fake data:
```
"--n (number of attacks)"
```
Open PowerShell in the project folder and run:
```
python simulate_attacks.py --n 10
```


This adds random IPs, countries, and command payloads into your database -  
perfect for screenshots, reports, or testing.

---

## 📂 Data Storage

| Location | Description |
|-----------|--------------|
| `hp_events.db` | SQLite database with all sessions and events |
| `transcripts/` | Plain text logs of each connection |
| `sessions_fs/` | Mini filesystem zips for each session |
| `geoip_cache.json` | IP → Country/ASN cache |

---

## ⚙️ Troubleshooting

**❌ Internal Server Error (Dashboard)**  
→ Check your PowerShell window for a Python traceback.  
Make sure:
- `APP.secret_key` is set in `dashboard.py`
- The database (`hp_events.db`) exists and has the right tables

**❌ Port in use (WinError 10048)**  
→ Another app is using the honeypot port. Run:
powershell
netstat -ano | findstr :2229
taskkill /PID <PID> /F

Then restart.

**❌ Dashboard empty**  
→ Run `test_client.py` or `simulate_attacks.py` and refresh.

---

## 🧠 Severity Levels (Explained)

| Severity | Meaning | Example Command |
|-----------|----------|----------------|
| 🟢 Low | Harmless | `ls`, `whoami` |
| 🟡 Medium | Slightly suspicious | `cat /etc/passwd` |
| 🟠 High | Active probing | `nmap`, `nc`, `sudo` |
| 🔴 Critical | Malicious intent | `rm -rf /`, `wget malware.sh` |

---

## 🛡️ Best Practices

- Change passwords and secret keys before exposure.  
- Never analyze downloaded payloads on your host.  
- Run behind a VM or sandbox.  
- Keep antivirus and firewall active.  
- Treat all honeypot data as *potentially hostile*.

---

## 💡 Future Enhancements

- Integrate a real ML model for threat classification  
- Add alert notifications (Slack, email, Telegram)  
- Filter and export logs by severity  
- Auto-generate reports or CSV summaries  

---

## 🪪 License & Disclaimer

This project is for **educational and research** use only.  
Use it responsibly and only on systems you own or have explicit permission to monitor.  
The author assumes **no liability** for misuse or damage resulting from deployment.
