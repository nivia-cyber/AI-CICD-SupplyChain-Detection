def calculate_risk(suspicious_count, entropy, prediction):
    score = 0

    if prediction == 1:
        score += 50

    score += suspicious_count * 10

    if entropy > 7.5:
        score += 20

    return min(score, 100)