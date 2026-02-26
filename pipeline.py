import os
import subprocess

print("Step 1: Generating build artifacts...")
subprocess.run(["python", "build_simulator.py"])

print("Step 2: Training ML model...")
subprocess.run(["python", "model_train.py"])

print("Step 3: Running detection on clean build...")
subprocess.run(["python", "detector.py"], input="dataset/clean/build_clean.txt\n", text=True)

print("Step 4: Running detection on compromised build...")
subprocess.run(["python", "detector.py"], input="dataset/compromised/build_compromised.txt\n", text=True)

print("Pipeline execution complete.")