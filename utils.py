# utils.py - Analyzer that calls external REST API and falls back to keyword rules
import requests, json, re
ANALYZER_URL = "http://127.0.0.1:9000/analyze"
TIMEOUT = 2.0

KEYWORDS = ['sudo','rm','wget','curl','nc','bash','root','ssh','passwd','nmap','exploit','docker']

def _fallback(command: str):
    if not command:
        return {'severity':'low','tags':[],'note':'empty'}
    txt = command.lower()
    tags = [k for k in KEYWORDS if re.search(r"\b" + re.escape(k) + r"\b", txt)]
    score = len(tags)
    if score >= 3:
        severity = 'critical'; note = f'ALERT: critical tokens ({",".join(tags)})'
    elif score == 2:
        severity = 'high'; note = f'ALERT: suspicious tokens ({",".join(tags)})'
    elif score == 1:
        severity = 'medium'; note = 'Permission denied.'
    else:
        severity = 'low'; note = 'OK'
    return {'severity': severity, 'tags': tags, 'note': note}

def analyze_event(command: str):
    try:
        resp = requests.post(ANALYZER_URL, json={'input': command}, timeout=TIMEOUT)
        if resp.status_code == 200:
            j = resp.json()
            return {
                'severity': j.get('severity', 'low'),
                'tags': j.get('tags', []),
                'note': j.get('note', str(j))
            }
    except Exception:
        pass
    return _fallback(command)
