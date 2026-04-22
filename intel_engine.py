import requests
import socket

def get_ip_intelligence(ip):

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=3)
        data = response.json()

        country = data.get("country", "Unknown")
        city = data.get("city", "Unknown")
        proxy = data.get("proxy", False)
        hosting = data.get("hosting", False)
        isp = data.get("isp", "Unknown")

    except:
        country = "Unknown"
        city = "Unknown"
        proxy = False
        hosting = False
        isp = "Unknown"

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "Unknown"

    if not isinstance(hostname, str):
        hostname = str(hostname)

    return country, city, hostname, proxy, hosting, isp