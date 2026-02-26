import hashlib
import os
import math

def calculate_entropy(data):
    if not data:
        return 0
    
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(file_path):
    with open(file_path, "r") as f:
        data = f.read()

    size = os.path.getsize(file_path)
    sha256 = hashlib.sha256(data.encode()).hexdigest()
    entropy = calculate_entropy(data)
    suspicious_keyword_count = data.count("MALICIOUS")

    return {
        "size": size,
        "entropy": entropy,
        "suspicious_count": suspicious_keyword_count,
        "hash": sha256
    }

if __name__ == "__main__":
    test_file = "dataset/clean/build_clean.txt"
    features = extract_features(test_file)
    print("Extracted Features:")
    print(features)