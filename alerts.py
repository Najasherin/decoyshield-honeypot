import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

SENDER_EMAIL = os.getenv("SENDER_EMAIL")
APP_PASSWORD = os.getenv("APP_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")


def send_email_alert(ip, level):
    if not SENDER_EMAIL or not APP_PASSWORD or not RECEIVER_EMAIL:
        print("Error: Email credentials not set")
        return
    try:
        subject = f"🚨 DecoyShield Alert - {level} Threat"
        body = f"""
        High Threat Detected!

        Attacker IP: {ip}
        Threat Level: {level}

        Please check DecoyShield Dashboard immediately.
        """

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.send_message(msg)
        server.quit()

        print("[EMAIL ALERT SENT]")

    except Exception as e:
        print("[EMAIL ERROR]", e)