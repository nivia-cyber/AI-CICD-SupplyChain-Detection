import subprocess
import json
import datetime
import hashlib
import joblib
import sys
from fingerprinting import extract_features

report = {}

print("🔹 Starting AI DevSecOps Pipeline...\n")

# -----------------------------
# Timestamp
# -----------------------------
report["timestamp"] = str(datetime.datetime.now())

# -----------------------------
# Step 1: Generate artifacts
# -----------------------------
print("Step 1: Generating build artifacts...")
subprocess.run(["python", "build_simulator.py"], check=True)

# -----------------------------
# Step 2: Train model
# -----------------------------
print("Step 2: Training ML model...")
subprocess.run(["python", "model_train.py"], check=True)

# -----------------------------
# Step 3: Run detection
# -----------------------------
print("Step 3: Running build detection...")

artifact_path = "dataset/clean/build_clean.txt"

model = joblib.load("model.pkl")
features = extract_features(artifact_path)

feature_vector = [[
    features["size"],
    features["entropy"],
    features["suspicious_count"]
]]

prediction = model.predict(feature_vector)

if prediction[0] == 0:
    build_status = "CLEAN"
else:
    build_status = "COMPROMISED"

report["artifact_analyzed"] = artifact_path
report["size"] = features["size"]
report["entropy"] = features["entropy"]
report["suspicious_count"] = features["suspicious_count"]
report["build_status"] = build_status

print(f"Build Status: {build_status}")

# -----------------------------
# Step 4: Model Integrity Hash
# -----------------------------
print("Step 4: Calculating model integrity hash...")

with open("model.pkl", "rb") as f:
    report["model_sha256"] = hashlib.sha256(f.read()).hexdigest()

# -----------------------------
# Save Security Report
# -----------------------------
with open("security_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\n✅ Security report generated: security_report.json")

# -----------------------------
# Enforce CI Failure
# -----------------------------
if build_status == "COMPROMISED":
    print("❌ Build compromised. Failing pipeline.")
    sys.exit(1)

print("🎉 Pipeline completed successfully.")