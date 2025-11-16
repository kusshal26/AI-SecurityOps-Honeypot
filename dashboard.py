#!/usr/bin/env python3
# dashboard.py — AI SecurityOps Honeypot Dashboard (Unlimited Events + Scrollable Honeypot + IST)

import os, sqlite3, json
from flask import Flask, render_template_string, request, redirect, url_for, session
from datetime import datetime
import pytz

APP = Flask(__name__)
APP.secret_key = "supersecretkey123"

USERNAME = "admin"
PASSWORD = "1234"
DB_FILE = os.path.join(os.path.dirname(__file__), "hp_events.db")

# ✅ Fixed timezone — India
TIMEZONE = pytz.timezone("Asia/Kolkata")

# ------------------------------------------------------
# HELPERS
# ------------------------------------------------------
def get_severity_color(severity):
    """Color-code event severity."""
    if not severity:
        return "white"
    s = severity.lower()
    if "critical" in s:
        return "#ff0033"
    elif "high" in s:
        return "#ff4500"
    elif "medium" in s:
        return "#ffa500"
    elif "low" in s:
        return "#00ff7f"
    return "white"

def format_time(ts):
    """Convert timestamp to IST format."""
    try:
        if isinstance(ts, str):
            dt = datetime.fromisoformat(ts)
        else:
            dt = datetime.fromtimestamp(ts)
        local_time = dt.astimezone(TIMEZONE)
        return local_time.strftime("%d-%b-%Y %H:%M:%S IST")
    except Exception:
        return str(ts)

def get_events():
    """Fetch all honeypot events (no limit)."""
    if not os.path.exists(DB_FILE):
        return []
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT e.ts, s.client_ip, s.client_port, s.country, e.payload, e.extra_json
        FROM events e
        JOIN sessions s ON s.id = e.session_id
        ORDER BY e.ts DESC
    """)
    rows = cur.fetchall()
    conn.close()

    events = []
    for r in rows:
        try:
            extra = json.loads(r["extra_json"]) if r["extra_json"] else {}
        except:
            extra = {}
        events.append({
            "ts": format_time(r["ts"]),
            "client": f"{r['client_ip']}:{r['client_port']}",
            "country": r["country"] or "Unknown",
            "payload": r["payload"],
            "severity": extra.get("severity", "Unknown")
        })
    return events

# ------------------------------------------------------
# ROUTES
# ------------------------------------------------------
@APP.route("/")
def index():
    if not session.get("logged"):
        return redirect(url_for("login"))

    auto_refresh = session.get("auto_refresh", True)
    events = get_events()
    last_updated = format_time(datetime.now())

    html = """
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <title>🧠 AI SecurityOps Honeypot Dashboard</title>
    <style>
        body {
            background-color: #0e0e0e;
            color: #ddd;
            font-family: Consolas, monospace;
            margin: 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px;
            border-bottom: 1px solid #333;
        }
        th {
            background-color: #1a1a1a;
        }
        tr:hover {
            background-color: #191919;
        }
        .header {
            background-color: #1a1a1a;
            padding: 15px;
            font-size: 18px;
            font-weight: bold;
            text-align: center;
            border-bottom: 2px solid #444;
        }
        .section-title {
            background-color: #1f1f1f;
            padding: 10px;
            font-weight: bold;
            margin-top: 20px;
            border-top: 1px solid #444;
            text-align: center;
        }
        button {
            background: #222;
            color: #fff;
            border: 1px solid #555;
            padding: 6px 10px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
        }
        button:hover { background: #444; }
        @keyframes pulseRed {
            0% { color: #ff0033; text-shadow: 0 0 4px #ff0033, 0 0 8px #ff0000; }
            50% { color: #ff4d4d; text-shadow: 0 0 10px #ff3333, 0 0 20px #ff1a1a; }
            100% { color: #ff0033; text-shadow: 0 0 4px #ff0033, 0 0 8px #ff0000; }
        }
        .critical-glow {
            font-weight: bold;
            animation: pulseRed 1s infinite;
        }
        .timestamp {
            text-align: center;
            color: #aaa;
            margin-top: 10px;
        }
        #honeypotContainer {
            height: 500px; /* ✅ Scrollable honeypot section */
            overflow-y: auto;
            border-top: 2px solid #333;
            margin: 0 20px;
            padding-right: 10px;
        }
    </style>
    {% if auto_refresh %}
      <meta http-equiv="refresh" content="5">
    {% endif %}
    </head>
    <body>
        <div class="header">🧠 AI SecurityOps Honeypot — Live Event Dashboard</div>

        <div style="text-align:center;margin:10px;">
            <form method="post" action="/toggle_refresh" style="display:inline;">
                <button type="submit">{% if auto_refresh %}🔄 Auto Refresh: ON{% else %}⏸️ Auto Refresh: OFF{% endif %}</button>
            </form>
            <form method="get" action="/refresh" style="display:inline;">
                <button type="submit">♻️ Refresh Now</button>
            </form>
            <form method="get" action="/logout" style="display:inline;">
                <button type="submit">🚪 Logout</button>
            </form>
        </div>

        <div class="timestamp">🕓 Last Updated: {{ last_updated }}</div>

        <div class="section-title">🧠 Honeypot Events (All Records)</div>
        <div id="honeypotContainer">
            <table>
                <tr><th>Time (IST)</th><th>Client</th><th>Country</th><th>Payload</th><th>Severity</th></tr>
                {% for e in events %}
                    <tr>
                        <td>{{ e.ts }}</td>
                        <td>{{ e.client }}</td>
                        <td>{{ e.country }}</td>
                        <td>{{ e.payload }}</td>
                        {% if 'critical' in e.severity.lower() %}
                            <td class="critical-glow">CRITICAL</td>
                        {% else %}
                            <td style="color: {{ get_severity_color(e.severity) }}; font-weight:bold;">
                                {{ e.severity.upper() }}
                            </td>
                        {% endif %}
                    </tr>
                {% endfor %}
            </table>
        </div>

        <script>
        // ✅ Auto-scroll Honeypot section
        const honeypotDiv = document.getElementById('honeypotContainer');
        if (honeypotDiv) honeypotDiv.scrollTop = honeypotDiv.scrollHeight;
        </script>
    </body>
    </html>
    """
    return render_template_string(html, events=events,
                                  auto_refresh=auto_refresh,
                                  last_updated=last_updated,
                                  get_severity_color=get_severity_color)

@APP.route("/toggle_refresh", methods=["POST"])
def toggle_refresh():
    session["auto_refresh"] = not session.get("auto_refresh", True)
    return redirect(url_for("index"))

@APP.route("/refresh")
def refresh():
    """Manual refresh endpoint."""
    return redirect(url_for("index"))

@APP.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == USERNAME and request.form.get("password") == PASSWORD:
            session["logged"] = True
            session["auto_refresh"] = True
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials"
    return render_template_string("""
    <html><body style='background:#0e0e0e;color:white;font-family:Consolas;text-align:center;padding-top:10%;'>
    <h2>🔐 Honeypot Dashboard Login</h2>
    <form method='post'>
        <input name='username' placeholder='Username' style='background:#1a1a1a;border:1px solid #555;color:white;padding:5px;margin:5px;'><br>
        <input type='password' name='password' placeholder='Password' style='background:#1a1a1a;border:1px solid #555;color:white;padding:5px;margin:5px;'><br>
        <button type='submit' style='background:#333;color:white;border:none;padding:8px 15px;border-radius:5px;'>Login</button>
    </form>
    {% if error %}<p style='color:red;'>{{ error }}</p>{% endif %}
    </body></html>
    """, error=error)

@APP.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    APP.run(host="0.0.0.0", port=8080, debug=True)
