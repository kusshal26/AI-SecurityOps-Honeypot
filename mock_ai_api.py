# mock_ai_api.py - lightweight mock analyzer server for testing
from flask import Flask, request, jsonify
import time
app = Flask("mock_ai")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    inp = data.get("input","")
    score = 0
    for k in ["sudo","rm","wget","curl","nc","bash","root","passwd","nmap","exploit"]:
        if k in inp.lower(): score += 1
    if score >= 3: severity = "critical"
    elif score == 2: severity = "high"
    elif score == 1: severity = "medium"
    else: severity = "low"
    tags = [t for t in ["sudo","rm","wget","curl","nc","bash","root","passwd","nmap","exploit"] if t in inp.lower()]
    time.sleep(0.12)
    return jsonify({"severity": severity, "tags": tags, "note": f"mocked {severity}"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=9000)
