# db.py - SQLite storage for sessions and events
import sqlite3, os
DB_FILE = os.path.join(os.path.dirname(__file__), "hp_events.db")

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
        extra_json TEXT,
        FOREIGN KEY(session_id) REFERENCES sessions(id)
    )
    """)
    conn.commit()
    conn.close()

def add_session(session_id, client_ip, client_port, start_ts, r_dns='', country='', asn=''):
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO sessions (id, client_ip, client_port, start_ts, r_dns, country, asn) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                (session_id, client_ip, client_port, start_ts, r_dns, country, asn))
    conn.commit(); conn.close()

def end_session(session_id, end_ts, notes=''):
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("UPDATE sessions SET end_ts = ?, notes = ? WHERE id = ?", (end_ts, notes, session_id))
    conn.commit(); conn.close()

def add_event(session_id, ts, kind, payload, tags='', extra_json=''):
    conn = sqlite3.connect(DB_FILE); cur = conn.cursor()
    cur.execute("INSERT INTO events (session_id, ts, kind, payload, tags, extra_json) VALUES (?, ?, ?, ?, ?, ?)", 
                (session_id, ts, kind, payload, tags, extra_json))
    conn.commit(); conn.close()
