from flask import Flask, render_template, request, jsonify
from datetime import datetime
from flask_mail import Mail, Message
import numpy as np
from sklearn.ensemble import IsolationForest
import json
from collections import Counter
import csv
from flask import Response
import re
import joblib
from waf_module.waf import detect_pattern, detect_ai_anomaly  
from collections import Counter

# the main Flask file. It connects everything—routes, logging, AI detection, 
# pattern checking, dashboard, export logs, and alert emails.

app = Flask(__name__)
LOG_FILE = "waf_logs.json"


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'oshadee265@gmail.com'   # replace
app.config['MAIL_PASSWORD'] = 'bicu qrlk qlef acnk'       # use app-specific password
app.config['MAIL_DEFAULT_SENDER'] = 'oshadee265@gamil.com'

mail = Mail(app)


model = joblib.load("model/waf_model.pkl")

# Logging
def log_request(ip, data, blocked, attack_type=None):
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "data": data,
        "blocked": blocked,
        "attack_type": attack_type  # ✅ don't change it based on blocked
    }

    try:
        with open(LOG_FILE, "r") as log_file:
            logs = json.load(log_file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w") as log_file:
        json.dump(logs, log_file, indent=4)

@app.route("/")
def index():
    return render_template("index.html")

# Home route (just a UI homepage)
@app.route("/analyze", methods=["POST"])
def analyze():
    # Accept input from either form field name
    user_input = request.form.get("user_input") or request.form.get("input") or ""
    print(f"Received input: {user_input}")
    
    # Pattern-based detection
    attack_type = detect_pattern(user_input)
    if attack_type:
        blocked = True
        result = f"Blocked: {attack_type}"
    else:
        # AI anomaly detection
        ai_suspicious = detect_ai_anomaly(user_input)
        if ai_suspicious:
            attack_type = "AI-Anomaly"
            blocked = True
            result = "Blocked: Anomalous Input"
        else:
            attack_type = "Normal"
            blocked = False
            result = "Allowed"

        # Log the result
    ip = request.remote_addr

    #  Alert if blocked
    if blocked:
        send_alert(ip, user_input, attack_type)

    log_request(ip, user_input, blocked, attack_type)

    

    # Detect if it's a curl or browser request
    if request.headers.get('User-Agent', '').startswith('curl'):
        return jsonify({"attack_type": attack_type, "result": result})
    else:
        return render_template("index.html", result=result)


@app.route("/test-ai", methods=["POST"])
def test_ai_direct():
    data = request.form.get("input", "")
    if not data:
        return jsonify({"error": "No input provided"}), 400
    result = detect_ai_anomaly(data)
    return jsonify({"input_length": len(data), "anomaly": result})


#  Dashboard route with date filtering
@app.route('/dashboard')
def dashboard():
    query = request.args.get('query', '').lower()
    blocked_filter = request.args.get('blocked', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    try:
        with open(LOG_FILE, "r") as log_file:
            logs = json.load(log_file)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)  # Sort the logs - newest first
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    filtered_logs = logs

    #  Search query filter
    if query:
        filtered_logs = [
            log for log in filtered_logs 
            if query in log['ip'].lower() or query in log['data'].lower()
        ]

    #  Blocked filter
    if blocked_filter == 'true':
        filtered_logs = [log for log in filtered_logs if log['blocked']]
    elif blocked_filter == 'false':
        filtered_logs = [log for log in filtered_logs if not log['blocked']]

    #  Date range filter
    if start_date and end_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.strptime(end_date, "%Y-%m-%d")

            filtered_logs = [
                log for log in filtered_logs
                if 'timestamp' in log and
                start_dt <= datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S") <= end_dt
            ]
        except Exception as e:
            print("Date filtering error:", e)

    #  Attack type count (only from filtered blocked logs)
    attack_counter = Counter(
    log['attack_type'] for log in filtered_logs
    if log['attack_type'] in ["SQL Injection", "XSS Attack", "AI-Anomaly", "Normal"]
)


    return render_template(
        'dashboard.html',
        logs=filtered_logs,
        attack_data=attack_counter
    )



@app.route("/requests")
def allowed_requests():
    try:
        with open(LOG_FILE, "r") as log_file:
            logs = json.load(log_file)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    allowed = [log for log in logs if log["blocked"] == False]
    return render_template("requests.html", logs=allowed)




@app.route("/attacks")
def blocked_requests():
    try:
        with open(LOG_FILE, "r") as log_file:
            logs = json.load(log_file)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    blocked = [log for log in logs if log["blocked"] == True]
    return render_template("attacks.html", logs=blocked)


import json

def load_logs():
    try:
        with open("waf_logs.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []
    

@app.route("/export/<log_type>")
def export_logs(log_type):
    logs = load_logs()

    if log_type == 'blocked':
        logs = [log for log in logs if log.get('blocked') == True]
    elif log_type == 'allowed':
        logs = [log for log in logs if log.get('blocked') == False]
    elif log_type == 'all':
        pass  # No filtering

    def generate():
        data = ["timestamp,ip,data,blocked,attack_type\n"]
        for log in logs:
            timestamp = log.get("timestamp", "")
            ip = log.get("ip", "")
            data_val = log.get("data", "").replace(",", ";")
            blocked = log.get("blocked", "")
            attack_type = log.get("attack_type", "")
            data.append(f"{timestamp},{ip},{data_val},{blocked},{attack_type}\n")
        return "".join(data)

    return Response(generate(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment;filename={log_type}_logs.csv"})

#alerts 
def send_alert(ip, data, attack_type):
    msg = Message(
        subject='🚨 WAF Alert: New Attack Detected',
        recipients=['oshadee265@gmail.com'],
        body=f"Attack Type: {attack_type}\nIP: {ip}\nData: {data}"
    )
    mail.send(msg)

@app.route('/attack-analysis')
def attack_analysis():
    try:
        with open(LOG_FILE, "r") as log_file:
            logs = json.load(log_file)
            logs.sort(key=lambda x: x['timestamp'], reverse=True)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    attack_counter = Counter(
        log['attack_type'] for log in logs
        if log['attack_type'] in ["SQL Injection", "XSS Attack", "AI-Anomaly", "Normal"]
    )

    return render_template('attack_analysis.html', logs=logs, attack_data=attack_counter)

if __name__ == "__main__":
    print(" Starting the Flask server...")
    app.run(debug=True, port=5000)


