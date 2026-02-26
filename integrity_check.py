import hashlib

def calculate_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

hash_value = calculate_hash("model.pkl")
print("Model SHA256:", hash_value)