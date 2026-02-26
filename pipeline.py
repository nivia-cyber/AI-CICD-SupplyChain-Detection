import subprocess
import json
import datetime
import joblib
import sys

from fingerprinting import extract_features
from risk_engine import calculate_risk

print("🔹 CI/CD Artifact Behavioral Validation Starting...\n")

report = {}
report["timestamp"] = str(datetime.datetime.now())

# ----------------------------------
# Step 1: Generate Build Artifact
# ----------------------------------
print("Step 1: Generating build artifact...")
subprocess.run(["python", "build_simulator.py"], check=True)

artifact_path = "dataset/current_build.txt"

# ----------------------------------
# Step 2: Load Trained Model
# ----------------------------------
print("Step 2: Loading ML model...")
model = joblib.load("model.pkl")

# ----------------------------------
# Step 3: Extract Behavioral Fingerprint
# ----------------------------------
print("Step 3: Extracting behavioral fingerprint...")
features = extract_features(artifact_path)

feature_vector = [[
    features["size"],
    features["entropy"],
    features["suspicious_count"]
]]

# ----------------------------------
# Step 4: AI Classification
# ----------------------------------
print("Step 4: Running AI anomaly detection...")
prediction = model.predict(feature_vector)[0]

status = "CLEAN" if prediction == 0 else "COMPROMISED"

# ----------------------------------
# Step 5: Risk Scoring
# ----------------------------------
risk_score = calculate_risk(
    suspicious_count=features["suspicious_count"],
    entropy=features["entropy"],
    prediction=prediction
)

# ----------------------------------
# Save Report
# ----------------------------------
report["artifact"] = artifact_path
report["status"] = status
report["risk_score"] = risk_score
report["features"] = features

with open("security_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\nValidation Result:")
print("Artifact Status:", status)
print("Risk Score:", risk_score)

# ----------------------------------
# CI/CD Gate Enforcement
# ----------------------------------
if risk_score >= 80:
    print("❌ Supply Chain Compromise Detected. Failing Pipeline.")
    sys.exit(1)

print("✅ Build Artifact Passed Security Validation.")