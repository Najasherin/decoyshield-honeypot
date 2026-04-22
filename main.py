import requests
import socket
import os
import threading
import time
from attacker_profile import classify_attacker
from database import init_db, log_attack
from datetime import datetime
from ports import generate_ports
from collections import defaultdict
running = True
service_banners = {
    21: b"220 FTP Server Ready\r\n",
    22: b"SSH-2.0-OpenSSH_8.2\r\n",
    23: b"Welcome to Telnet Service\r\n",
    25: b"220 SMTP Mail Server\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n",
    443: b"HTTP/1.1 200 OK\r\nServer: Nginx\r\n\r\n"
}
ip_activity = defaultdict(list)
ip_ports = defaultdict(set)
ip_scores = defaultdict(int)
active_ports = generate_ports()
KNOCK_SEQUENCE = [1111, 2222, 3333]
AUTHORIZED_IPS = {}
knock_attempts = defaultdict(list)
REAL_SERVICE_PORT = 8080
for p in KNOCK_SEQUENCE + [REAL_SERVICE_PORT]:
    if p not in active_ports:
        active_ports.append(p)
print(f"[+] DECOYSHIELD Starting with {len(active_ports)} ports")

def get_ip_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()

        country = data.get("country", "Unknown")
        city = data.get("city", "Unknown")
        proxy = data.get("proxy", False)
        hosting = data.get("hosting", False)
        isp = data.get("isp", "Unknown")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "Unknown"

        if not isinstance(hostname, str):
            hostname = str(hostname)

        return country, city, hostname, proxy, hosting, isp

    except:
        return "Unknown", "Unknown", "Unknown", False, False, "Unknown"

def check_ip_reputation(ip):
    API_KEY = os.getenv("ABUSE_API_KEY")

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()["data"]

        confidence = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)

        return confidence, reports

    except:
        return 0, 0    
    
def handle_client(conn, addr, port):
    ip = addr[0]
    conn.settimeout(10)
    commands_used=[]
    if ip in AUTHORIZED_IPS:
        if time.time()-AUTHORIZED_IPS[ip] <60:
            if port == REAL_SERVICE_PORT:
                conn.send(b"Welcome to the real service\n")
                conn.close()
                return
  
    if port in KNOCK_SEQUENCE:
        knock_attempts[ip].append(port)
    
        knock_attempts[ip] = knock_attempts[ip][-len(KNOCK_SEQUENCE):]

        if knock_attempts[ip][-len(KNOCK_SEQUENCE):]==KNOCK_SEQUENCE:
            print(f"[PORT KNOCK SUCCESS] {ip} authenticated")

            log_attack(
                ip=ip,
                port=0,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                attack_type="Authorized Access (Port Knock)",
                score=0,
                threat_level="LOW",
                country="Trusted",
                city="Trusted",
                hostname="Authorized User",
                confidence=0,
                reports=0,
                session_duration=1,
                intent="Authorized Access",
                attacker_type="Whitelisted User"
            )
            AUTHORIZED_IPS[ip] = time.time()
            knock_attempts[ip] = []
        conn.close()
        return
    session_start = time.time()

    country, city, hostname, proxy, hosting, isp = get_ip_info(ip)
    confidence, reports = check_ip_reputation(ip)

    print(f"\n[!] Connection detected")
    print(f"    IP       : {ip}")
    print(f"    Country  : {country}")
    print(f"    City     : {city}")
    print(f"    Hostname : {hostname}")
    print(f"    Port     : {port}")
    print(f"    Proxy    : {proxy}")
    print(f"    Hosting  : {hosting}")
    print(f"    ISP      : {isp}")
    print(f"    Abuse Confidence : {confidence}%")
    print(f"    Total Reports    : {reports}")

    current_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    ip_activity[ip].append(current_time)
    ip_activity[ip] = ip_activity[ip][-10:]
    ip_ports[ip].add(port)

    score, level, attack_type = calculate_threat_score(ip)
    intent = attack_type
    attacker_type = classify_attacker(
        intent=intent,
        confidence=confidence,
        threat="LOW",
        attack_count=0,
        commands=""
    )
    print(f"[Intent]: {intent}")
    print(f"[Attacker Profile]: {attacker_type}")

    if level == "LOW":
        response_delay = 0.5
    elif level == "MEDIUM":
        response_delay = 2
    else:
        response_delay = 4

    print(f"[ADAPTIVE] {ip} | Level: {level} | Delay: {response_delay}s")
    time.sleep(response_delay)

    if port == REAL_SERVICE_PORT:
        conn.send(b"Welcome to Real Protected Service\n")
        conn.close()
        return
    try:
       
        if level == "HIGH":
            conn.send(b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.8 (Old)\r\n\r\n")
            conn.send(b"\nWelcome to Legacy Admin Console\n")
            conn.send(b"login: ")

            conn.settimeout(15)

            try:
                username = conn.recv(1024)
                conn.send(b"password: ")
                password = conn.recv(1024)

                conn.send(b"\nLogin successful!\n")
                conn.send(b"root@server:~# ")
                while True:
                    cmd = conn.recv(1024)
                    if not cmd:
                        break

                    decoded_cmd = cmd.decode(errors="ignore").strip()
                    print(f"[SANDBOX CMD] {ip} -> {decoded_cmd}")
                    commands_used.append(decoded_cmd)
                    if "whoami" in decoded_cmd:
                        conn.send(b"root\n")
                    elif "ls" in decoded_cmd:
                        conn.send(b"admin.txt  passwords.db  config.bak\n")
                    elif "cat" in decoded_cmd:
                        conn.send(b"Access Denied\n")
                    elif "exit" in decoded_cmd:
                        conn.send(b"Logout\n")
                        break
                    else:
                        conn.send(b"Command executed.\n")

                    conn.send(b"root@server:~# ")

            except:
                pass

        elif level == "MEDIUM":
            banner = b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n"
            conn.send(banner)

        else:
            banner = service_banners.get(port, b"Service Ready\r\n")
            conn.send(banner)

        conn.settimeout(5)
        try:
            data = conn.recv(1024)
            if data:
                decoded_data = data.decode(errors="ignore").strip()
                print(f"[ATTACKER DATA] {decoded_data}")
        except socket.timeout:
            pass

    except:
        pass

    finally:
        session_end = time.time()
        session_duration = round(session_end - session_start, 2)

        print(f"[SESSION] IP: {ip} | Duration: {session_duration}s")
        command_history="\n".join(commands_used)
        print("saving log to database...")
        log_attack(
            ip=ip,
            port=port,
            timestamp=timestamp,
            attack_type=attack_type,
            score=score,
            threat_level=level,
            country=country,
            city=city,
            hostname=hostname,
            confidence=confidence,
            reports=reports,
            session_duration=session_duration,
            intent=intent,
            attacker_type=attacker_type,
            commands=command_history
        )

        conn.close()

def calculate_threat_score(ip):
    score = 0
  
    port_count = len(ip_ports[ip])
    if port_count > 5:
        score += 40
    elif port_count > 2:
        score += 20

    timestamps = ip_activity[ip]
    if len(timestamps) > 1:
        time_diffs = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]
        avg_diff = sum(time_diffs) / len(time_diffs)
        if avg_diff < 6:
            score += 40
        elif avg_diff < 10:
            score += 20
   
    if len(timestamps) > 8:
        score += 20
    ip_scores[ip]=score
    level=classify_threat(ip, score)
    attack_type=detect_attack_type(ip)
    return score, level, attack_type

def classify_threat(ip, score):
    if score >= 60:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"
    print(f"[THREAT LEVEL] IP: {ip} | Score: {score} | Level: {level}")
    return level  

def detect_attack_type(ip):
    port_count = len(ip_ports[ip])
    timestamps = ip_activity[ip]

    if port_count > 5:
        attack_type = "HORIZONTAL PORT SCAN"
    elif len(timestamps) > 10:
        attack_type = "VERTICAL BRUTE-FORCE"
    else:
        attack_type = "RECON / LOW ACTIVITY"

    print(f"[ATTACK TYPE] IP: {ip} | {attack_type}")
    return attack_type  

def start_listener(port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", port))
        server.listen(5)

        print(f"[+] Successfully listening on port {port}")

        while running:
            conn, addr = server.accept()
        
            if port == REAL_SERVICE_PORT:
                ip = addr[0]
                if ip not in AUTHORIZED_IPS:
                    print(f"[BLOCKED] Unauthorized access attempt from {ip}")
                    conn.close()
                    continue
                else:
                    print(f"[ACCESS GRANTED] Real service opened for {ip}")
            threading.Thread(
                target=handle_client,
                args=(conn, addr, port),
                daemon=True
            ).start()

    except OSError as e:
        print(f"[SKIPPED] Port {port} already in use.")

def stop_honeypot():
    global running
    running = False

def main():
    init_db()

    print("[+] Starting listeners...")

    for port in active_ports:
        threading.Thread(
            target=start_listener,
            args=(port,),
            daemon=False   
        ).start()
        time.sleep(0.05)
    print("[+] Honeypot running... Press Ctrl+C to stop.")

    while True:
        time.sleep(1)
def start_honeypot():
    main()
if __name__ == "__main__":
    main()    