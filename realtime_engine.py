import os
import time
import json
from datetime import datetime
from anomaly_engine import detect_anomaly
from mitre_engine import map_to_mitre
from risk_engine import calculate_risk

LOG_FOLDER = "logs"
REPORT_FILE = "security_report.json"

def process_log(file_path):
    with open(file_path, "r") as f:
        content = f.read()

    anomaly_score = detect_anomaly(content)
    mitre_techniques = map_to_mitre(content)
    risk_score = calculate_risk(anomaly_score, mitre_techniques)

    report = {
        "timestamp": str(datetime.now()),
        "log_file": file_path,
        "anomaly_score": anomaly_score,
        "mitre_techniques": mitre_techniques,
        "risk_score": risk_score
    }

    # ---------- Append to history instead of overwrite ----------
    if os.path.exists(REPORT_FILE):
        with open(REPORT_FILE, "r") as f:
            try:
                data = json.load(f)
            except:
                data = []
    else:
        data = []

    if not isinstance(data, list):
        data = []

    data.append(report)

    with open(REPORT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print(f"[+] Processed {file_path} | Risk Score: {risk_score}")


def monitor_logs():
    print("🔴 Real-Time Monitoring Started...\n")
    processed = set()

    while True:
        files = os.listdir(LOG_FOLDER)

        for file in files:
            if file not in processed:
                process_log(os.path.join(LOG_FOLDER, file))
                processed.add(file)

        time.sleep(2)


if __name__ == "__main__":
    monitor_logs()