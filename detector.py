import joblib
import sys
import json
from fingerprinting import extract_features

# Load model
model = joblib.load("model.pkl")

file_path = input("Enter path of build artifact: ")

features = extract_features(file_path)

feature_vector = [[
    features["size"],
    features["entropy"],
    features["suspicious_count"]
]]

prediction = model.predict(feature_vector)

result = "CLEAN" if prediction[0] == 0 else "COMPROMISED"

print(f"Build is {result}")

# Save report for dashboard
report = {
    "file": file_path,
    "size": features["size"],
    "entropy": features["entropy"],
    "suspicious_count": features["suspicious_count"],
    "status": result
}

with open("report.json", "w") as f:
    json.dump(report, f, indent=4)

# Fail CI if compromised
if result == "COMPROMISED":
    sys.exit(1)