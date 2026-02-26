import os
import random

# Make sure dataset folder exists
os.makedirs("dataset", exist_ok=True)

artifact_path = "dataset/current_build.txt"

# Simulate either clean or compromised build randomly
clean_content = [
    "application start",
    "user login",
    "data processing"
]

compromised_content = [
    "application start",
    "whoami",
    "powershell -enc attack",
    "nc 10.0.0.5 4444"
]

# Randomly choose build type
if random.choice([True, False]):
    content = clean_content
    print("Generated CLEAN build")
else:
    content = compromised_content
    print("Generated COMPROMISED build")

with open(artifact_path, "w") as f:
    for line in content:
        f.write(line + "\n")

print("Build artifact generated at:", artifact_path)