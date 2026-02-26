import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from fingerprinting import extract_features

print("Training model...")

clean = extract_features("dataset/clean/build_clean.txt")
comp = extract_features("dataset/compromised/build_compromised.txt")

X = [
    [clean["size"], clean["entropy"], clean["suspicious_count"]],
    [comp["size"], comp["entropy"], comp["suspicious_count"]]
]

y = [0, 1]

model = RandomForestClassifier()
model.fit(X, y)

joblib.dump(model, "model.pkl")

print("Model trained successfully.")
print("Saved at:", os.path.abspath("model.pkl"))