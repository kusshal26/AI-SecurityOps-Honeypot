#!/usr/bin/env python3
# main.py - AI Honeypot core engine with auto port retry + event severity tagging

import socket
import threading
import sqlite3
import time
import json
import os
import errno
import requests
import sqlite3, json, time, uuid, os
from utils import analyze_event

DB_FILE = os.path.join(os.path.dirname(__file__), 'hp_events.db')

def save_event(session_id, payload):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        analysis = analyze_event(payload)
        extra_json = json.dumps(analysis)
        cur.execute("INSERT INTO events (session_id, ts, payload, extra_json) VALUES (?, ?, ?, ?)",
                    (session_id, ts, payload, extra_json))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] {e}")

def create_session(client_ip, client_port):
    sid = str(uuid.uuid4())
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO sessions (id, client_ip, client_port, start_ts) VALUES (?, ?, ?, ?)",
                (sid, client_ip, client_port, ts))
    conn.commit()
    conn.close()
    return sid


GEO_CACHE_FILE = "geoip_cache.json"

def geoip_lookup(ip: str):
    """Fetch GeoIP info for an IP and cache results."""
    if os.path.exists(GEO_CACHE_FILE):
        try:
            with open(GEO_CACHE_FILE, "r") as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    else:
        cache = {}

    if ip in cache:
        return cache[ip]

    data = {"country": "Unknown", "asn": "Unknown"}
    try:
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            data = {"country": "Local", "asn": "Private Network"}
        else:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,as,query", timeout=2)
            if r.status_code == 200:
                j = r.json()
                if j.get("status") == "success":
                    flag = j.get("countryCode", "")
                    emoji = f"🇺🇸" if flag == "US" else f"🇮🇳" if flag == "IN" else ""
                    data = {"country": f"{emoji} {j.get('country','')}", "asn": j.get("as", "")}
    except Exception as e:
        print(f"[!] GeoIP lookup failed for {ip}: {e}")

    cache[ip] = data
    with open(GEO_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

    return data


DB_FILE = "hp_events.db"
HOST = "0.0.0.0"
PORT = 2229  # Default honeypot port

# ==============================================
# Ensure DB exists
# ==============================================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            client_ip TEXT,
            client_port INTEGER,
            start_ts TEXT,
            end_ts TEXT,
            r_dns TEXT,
            country TEXT,
            asn TEXT,
            notes TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ts TEXT,
            kind TEXT,
            payload TEXT,
            tags TEXT,
            extra_json TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ==============================================
# Event Logger (handles all severities)
# ==============================================
def log_event(session_id, kind, payload, tags=""):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()

    # Always assign a default severity
    severity = "low"

    # Escalate severity based on content
    payload_l = payload.lower()
    if any(x in payload_l for x in ["rm -rf", "wget", "curl http", "chmod 777", "python -c"]):
        severity = "critical"
    elif any(x in payload_l for x in ["sudo", "nmap", "nc ", "bash", "cat /etc/passwd"]):
        severity = "high"

    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    cur.execute(
        "INSERT INTO events (session_id, ts, kind, payload, tags, extra_json) VALUES (?, ?, ?, ?, ?, ?)",
        (session_id, ts, kind, payload, tags, json.dumps({"severity": severity}))
    )

    conn.commit()
    conn.close()

    print(f"[LOG] {session_id} | {severity.upper()} | {payload}")

# ==============================================
# Handle individual client connections
# ==============================================
def handle_client(conn, addr):
    client_ip, client_port = addr
    session_id = f"{client_ip}-{client_port}-{int(time.time())}"
    print(f"[*] Connection from {client_ip}:{client_port}")

    # Register session
    # Lookup GeoIP info
    geo = geoip_lookup(client_ip)
    country = geo.get("country", "Unknown")
    asn = geo.get("asn", "Unknown")

    # Register session with GeoIP data
    conn_db = sqlite3.connect(DB_FILE)
    cur = conn_db.cursor()
    cur.execute("INSERT OR REPLACE INTO sessions (id, client_ip, client_port, start_ts, country, asn) VALUES (?,?,?,?,?,?)",(session_id, client_ip, client_port, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), country, asn))

    conn_db.commit()
    conn_db.close()

    try:
        conn.sendall(b"Welcome to Secure SSH Server v7.4\r\n")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            payload = data.decode(errors="ignore").strip()
            if payload:
                log_event(session_id, "recv", payload)
                conn.sendall(b"OK\r\n")
    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected {client_ip}:{client_port}")

# ==============================================
# Start honeypot with auto port fallback
# ==============================================
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    base_port = PORT
    retries = 5
    bound = False

    for i in range(retries):
        try:
            sock.bind((HOST, base_port + i))
            final_port = base_port + i
            print(f"[*] Honeypot bound to port {final_port}")
            bound = True
            break
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                print(f"[!] Port {base_port + i} already in use. Trying next...")
                continue
            else:
                raise

    if not bound:
        print("[X] Could not bind to any available port. Exiting.")
        return

    sock.listen(5)
    print(f"[+] Honeypot active on {HOST}:{final_port}. Waiting for connections...")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr))
            t.daemon = True
            t.start()
        except KeyboardInterrupt:
            print("\n[!] Honeypot shutting down.")
            break
        except Exception as e:
            print(f"[!] Error in main loop: {e}")

if __name__ == "__main__":
    start_server()
