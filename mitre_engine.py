def map_to_mitre(content):
    content = content.lower()

    techniques = []

    if "mimikatz" in content:
        techniques.append("T1003 - Credential Dumping")

    if "powershell" in content:
        techniques.append("T1059 - Command Execution")

    if "whoami" in content:
        techniques.append("T1033 - Account Discovery")

    if "nc -e" in content:
        techniques.append("T1105 - Ingress Tool Transfer")

    if "base64" in content:
        techniques.append("T1027 - Obfuscated Files")

    return techniques