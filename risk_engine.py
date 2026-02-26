import random

def calculate_risk(detection_result):
    base_score = random.uniform(0.5, 0.9)

    if detection_result == "COMPROMISED":
        return round(base_score, 2)
    else:
        return round(random.uniform(0.1, 0.4), 2)