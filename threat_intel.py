import requests
import os
ABUSE_API_KEY=os.getenv("ABUSE_API_KEY")
def check_abuse_ip(ip):
    if not ABUSE_API_KEY:
        print("Error: Abuse API key not set")
        return 0, 0
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()["data"]
        confidence =data["abuseConfidenceScore"]
        reports = data["totalReports"]
        return confidence, reports
        
    except:
        return 0, 0
def enrich_threat(ip, confidence, reports, behavior=None, is_vpn=False):

    risk_score = 0

    
    risk_score += confidence * 0.4
    risk_score += min(reports, 50) * 0.2

    
    if behavior == "ATTACKER":
        risk_score += 20

    if is_vpn:
        risk_score += 15

    risk_score = min(risk_score, 100)

    return {
        "risk_score": risk_score
    }