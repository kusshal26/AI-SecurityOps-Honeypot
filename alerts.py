# alerts.py - stub for Slack/email alerts
def on_alert(session_id, severity, details):
    # Implement Slack webhook or SMTP alert here.
    print(f"ALERT HOOK: session={session_id} severity={severity} details={details}")
