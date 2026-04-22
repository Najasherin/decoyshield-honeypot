import sqlite3

DB_NAME = "decoyshield.db"

def get_total_attacks(cursor):
    cursor.execute("SELECT COUNT(*) FROM attacks")
    return cursor.fetchone()[0]

def get_top_attacker(cursor):
    cursor.execute("""
        SELECT ip, COUNT(*) as attack_count
        FROM attacks
        GROUP BY ip
        ORDER BY attack_count DESC
        LIMIT 1
    """)
    return cursor.fetchone()

def get_highest_confidence(cursor):
    cursor.execute("""
        SELECT ip, abuse_confidence
        FROM attacks
        ORDER BY abuse_confidence DESC
        LIMIT 1
    """)
    return cursor.fetchone()

def get_threat_distribution(cursor):
    cursor.execute("""
        SELECT threat_level, COUNT(*)
        FROM attacks
        GROUP BY threat_level
    """)
    return cursor.fetchall()

def get_most_targeted_port(cursor):
    cursor.execute("""
        SELECT port, COUNT(*) as port_count
        FROM attacks
        GROUP BY port
        ORDER BY port_count DESC
        LIMIT 1
    """)
    return cursor.fetchone()

def show_dashboard():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    print("\n========== DECOYSHIELD CLI DASHBOARD ==========")

    total = get_total_attacks(cursor)
    print(f"\nTotal Attacks Logged: {total}")

    top_ip = get_top_attacker(cursor)
    if top_ip:
        print(f"\nTop Attacking IP:")
        print(f"  {top_ip[0]} ({top_ip[1]} attempts)")

    high_conf = get_highest_confidence(cursor)
    if high_conf:
        print(f"\nHighest Abuse Confidence:")
        print(f"  {high_conf[0]} ({high_conf[1]}%)")

    distribution = get_threat_distribution(cursor)
    print(f"\nThreat Level Distribution:")
    for level, count in distribution:
        print(f"  {level} : {count}")

    top_port = get_most_targeted_port(cursor)
    if top_port:
        print(f"\nMost Targeted Port:")
        print(f"  {top_port[0]} ({top_port[1]} hits)")

    print("\n===============================================")

    conn.close()

if __name__ == "__main__":
    show_dashboard()