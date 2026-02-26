import subprocess
import json
import datetime
import hashlib
import joblib
from fingerprinting import extract_features

report = {}

# Timestamp
report["timestamp"] = str(datetime.datetime.now())

# Step 1: Generate artifacts
subprocess.run(["python", "build_simulator.py"], check=True)

# Step 2: Train model
subprocess.run(["python", "model_train.py"], check=True)

# Step 3: Run detection on clean build
model = joblib.load("model.pkl")
features = extract_features("dataset/clean/build_clean.txt")

feature_vector = [[
    features["size"],
    features["entropy"],
    features["suspicious_count"]
]]

prediction = model.predict(feature_vector)

if prediction[0] == 0:
    report["build_status"] = "CLEAN"
else:
    report["build_status"] = "COMPROMISED"

# Step 4: Generate model hash
with open("model.pkl", "rb") as f:
    report["model_sha256"] = hashlib.sha256(f.read()).hexdigest()

# Save report
with open("security_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("Security report generated.")