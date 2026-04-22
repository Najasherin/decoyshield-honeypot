def classify_attacker(intent, confidence, threat, attack_count=0, commands="",ip=""):
    if ip.startswith(("127.","192.168","10.")):
        return "local/test traffic"
  
    if confidence == 0 and attack_count<3:
        return "Local/Test Traffic"

    if threat == "HIGH" and attack_count > 15:
        return "Automated Scanner (Nmap/Bot)"

   
    if intent == "Scan" and attack_count > 5:
        return "Reconnaissance Actor"

 
    if commands:
        if "whoami" in commands or "ls" in commands:
            return "Manual Attacker (Interactive)"

        if "cat /etc/passwd" in commands or "password" in commands:
            return "Credential Harvester"

    if confidence > 70:
        return "Known Malicious Actor"

    elif confidence > 30:
        return "Suspicious Actor"

    return "Unknown"