import sys
import joblib
from fingerprinting import extract_features

def main():
    try:
        # Load trained model
        model = joblib.load("model.pkl")
    except Exception as e:
        print("❌ Failed to load model:", e)
        sys.exit(2)  # Critical failure

    file_path = input("Enter path of build artifact: ")

    try:
        features = extract_features(file_path)
    except Exception as e:
        print("❌ Feature extraction failed:", e)
        sys.exit(2)

    feature_vector = [[
        features["size"],
        features["entropy"],
        features["suspicious_count"]
    ]]

    prediction = model.predict(feature_vector)

    if prediction[0] == 0:
        print("✅ Build is CLEAN")
        sys.exit(0)   # Success
    else:
        print("🚨 Build is COMPROMISED")
        sys.exit(1)   # ❗ This FAILS GitHub Actions


if __name__ == "__main__":
    main()