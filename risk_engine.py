def calculate_risk(suspicious_count, entropy, prediction):
    score = 0

    # AI prediction weight
    if prediction == 1:
        score += 50

    # Suspicious keyword weight
    score += suspicious_count * 10

    # High entropy indicator
    if entropy > 4.5:
        score += 20

    return min(score, 100)


def classify_severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"