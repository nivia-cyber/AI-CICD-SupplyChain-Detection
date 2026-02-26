import subprocess
import json
import datetime
import joblib
import sys

from fingerprinting import extract_features
from attack_engine import generate_attack
from mutation_engine import mutate_attack
from risk_engine import calculate_risk

report = {}

print("🔹 Starting Adaptive Security Validation Pipeline...\n")

report["timestamp"] = str(datetime.datetime.now())

# ----------------------------------
# Step 1: Generate artifacts
# ----------------------------------
print("Step 1: Generating build artifacts...")
subprocess.run(["python", "build_simulator.py"], check=True)

# ----------------------------------
# Step 2: Train ML model
# ----------------------------------
print("Step 2: Training ML model...")
subprocess.run(["python", "model_train.py"], check=True)

model = joblib.load("model.pkl")

# ----------------------------------
# Step 3: Simulate polymorphic attack
# ----------------------------------
print("Step 3: Generating polymorphic attack...")
attack = generate_attack()
attack = mutate_attack(attack)

report["simulated_attack"] = attack

# ----------------------------------
# Step 4: Test CLEAN build
# ----------------------------------
print("Step 4: Testing CLEAN build...")
clean_path = "dataset/clean/build_clean.txt"

clean_features = extract_features(clean_path)
clean_vector = [[
    clean_features["size"],
    clean_features["entropy"],
    clean_features["suspicious_count"]
]]

clean_prediction = model.predict(clean_vector)[0]
clean_status = "CLEAN" if clean_prediction == 0 else "COMPROMISED"

# ----------------------------------
# Step 5: Test COMPROMISED build
# ----------------------------------
print("Step 5: Testing COMPROMISED build...")
comp_path = "dataset/compromised/build_compromised.txt"

comp_features = extract_features(comp_path)
comp_vector = [[
    comp_features["size"],
    comp_features["entropy"],
    comp_features["suspicious_count"]
]]

comp_prediction = model.predict(comp_vector)[0]
comp_status = "CLEAN" if comp_prediction == 0 else "COMPROMISED"

# ----------------------------------
# Risk Calculation
# ----------------------------------
risk_score = calculate_risk(comp_status)

report["clean_test"] = clean_status
report["compromised_test"] = comp_status
report["risk_score"] = risk_score

# ----------------------------------
# Save report
# ----------------------------------
with open("security_report.json", "w") as f:
    json.dump(report, f, indent=4)

print("\nTest Results:")
print("Clean Build:", clean_status)
print("Compromised Build:", comp_status)
print("Risk Score:", risk_score)

# ----------------------------------
# Enforcement Logic (CI/CD Gate)
# ----------------------------------
if clean_status != "CLEAN":
    print("❌ ERROR: Clean build misclassified!")
    sys.exit(1)

if comp_status != "COMPROMISED":
    print("❌ ERROR: Compromised build NOT detected!")
    sys.exit(1)

print("✅ Adaptive Security validation successful.")