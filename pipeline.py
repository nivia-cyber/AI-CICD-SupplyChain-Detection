import subprocess
import json
import datetime
import joblib
import sys
import hashlib

from fingerprinting import extract_features
from risk_engine import calculate_risk, classify_severity

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

severity = classify_severity(risk_score)

# ----------------------------------
# Step 6: MITRE Mapping
# ----------------------------------
detected_techniques = []

with open(artifact_path, "r") as f:
    content = f.read().lower()

if "powershell" in content:
    detected_techniques.append("T1059 - Command Execution")

if "whoami" in content:
    detected_techniques.append("T1033 - Account Discovery")

if "nc" in content:
    detected_techniques.append("T1105 - Ingress Tool Transfer")

if "mimikatz" in content:
    detected_techniques.append("T1003 - Credential Dumping")

# ----------------------------------
# Step 7: SHA256 Hashing
# ----------------------------------
with open(artifact_path, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()

# ----------------------------------
# Save Report
# ----------------------------------
report["artifact"] = artifact_path
report["status"] = status
report["risk_score"] = risk_score
report["severity"] = severity
report["sha256"] = file_hash
report["mitre_techniques"] = detected_techniques
report["features"] = features

with open("security_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\nValidation Result:")
print("Artifact Status:", status)
print("Risk Score:", risk_score)
print("Severity:", severity)

# ----------------------------------
# CI/CD Gate Enforcement
# ----------------------------------
if severity in ["CRITICAL", "HIGH"]:
    print("❌ Supply Chain Compromise Detected. Failing Pipeline.")
    sys.exit(1)

elif severity == "MEDIUM":
    print("⚠ Medium Risk Detected. Manual Review Recommended.")

else:
    print("✅ Build Artifact Passed Security Validation.")