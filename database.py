import sqlite3

import os
import sys

BASE_DIR = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(__file__)
DB_NAME = os.path.join(BASE_DIR, "decoyshield.db")



def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS attacks")

    cursor.execute("""
        CREATE TABLE attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            timestamp TEXT,
            attack_type TEXT,
            score INTEGER,
            threat_level TEXT,
            country TEXT,
            city TEXT,
            hostname TEXT,
            abuse_confidence INTEGER,
            total_reports INTEGER,
            session_duration REAL,
            intent TEXT,
            attacker_type TEXT,
            commands TEXT
        )
    """)

    conn.commit()
    conn.close()

    print("Database reset and ready")


def log_attack(ip, port, timestamp, attack_type, score, threat_level,
               country, city, hostname, confidence, reports,
               session_duration, intent, attacker_type, commands):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO attacks
        (ip, port, timestamp, attack_type, score, threat_level,
        country, city, hostname, abuse_confidence, total_reports,
        session_duration, intent, attacker_type, commands)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        port,
        timestamp,
        attack_type,
        score,
        threat_level,
        country,
        city,
        hostname,
        confidence,
        reports,
        session_duration,
        intent,
        attacker_type,
        commands
    ))
    attack_id=cursor.lastrowid
    conn.commit()
    conn.close()
    return attack_id

def update_attacker_type(attack_id, attacker):
    import sqlite3
    conn = sqlite3.connect("decoyshield.db")
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE attacks
        SET attacker_type = ?
        WHERE id = ?
    """, (attacker, attack_id))

    conn.commit()
    conn.close()

def update_commands(attack_id, commands):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE attacks
        SET commands = ?
        WHERE id = ?
    """, (commands, attack_id))

    conn.commit()
    conn.close()