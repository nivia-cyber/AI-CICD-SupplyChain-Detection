import random
import hashlib

def generate_dependency_attack():
    malicious_versions = ["0.0.1", "99.99.99", "1.3.7"]
    return {
        "attack_type": "Dependency Poisoning",
        "version": random.choice(malicious_versions)
    }

def generate_artifact_tampering():
    fake_hash = hashlib.sha256(str(random.random()).encode()).hexdigest()
    return {
        "attack_type": "Artifact Tampering",
        "fake_hash": fake_hash
    }

def generate_attack():
    attacks = [
        generate_dependency_attack,
        generate_artifact_tampering
    ]
    return random.choice(attacks)()