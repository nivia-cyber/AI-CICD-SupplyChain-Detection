def detect_anomaly(content):
    content = content.lower()

    score = 0

    suspicious_keywords = [
        "mimikatz",
        "powershell -enc",
        "nc -e",
        "base64",
        "whoami",
        "cmd.exe",
        "attack"
    ]

    for keyword in suspicious_keywords:
        if keyword in content:
            score += 20

    return min(score, 100)