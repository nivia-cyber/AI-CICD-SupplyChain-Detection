import joblib
from fingerprinting import extract_features

# Load trained model
model = joblib.load("model.pkl")

file_path = input("Enter path of build artifact: ")

features = extract_features(file_path)

feature_vector = [[
    features["size"],
    features["entropy"],
    features["suspicious_count"]
]]

prediction = model.predict(feature_vector)

if prediction[0] == 0:
    print("Build is CLEAN")
else:
    print("Build is COMPROMISED")