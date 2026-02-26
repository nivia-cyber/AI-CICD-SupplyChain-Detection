import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from fingerprinting import extract_features

X = []
y = []

# Clean builds (label = 0)
for file in os.listdir("dataset/clean"):
    path = os.path.join("dataset/clean", file)
    features = extract_features(path)
    X.append([features["size"], features["entropy"], features["suspicious_count"]])
    y.append(0)

# Compromised builds (label = 1)
for file in os.listdir("dataset/compromised"):
    path = os.path.join("dataset/compromised", file)
    features = extract_features(path)
    X.append([features["size"], features["entropy"], features["suspicious_count"]])
    y.append(1)

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "model.pkl")

print("Model trained and saved successfully.")