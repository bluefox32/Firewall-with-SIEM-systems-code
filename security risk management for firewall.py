import os
import json
import logging
from logging.handlers import SysLogHandler
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = SysLogHandler(address='/dev/log')
logger.addHandler(handler)

# Function to collect logs
def collect_logs():
    logs = []
    log_path = '/var/log/syslog'  # Example path for syslog
    with open(log_path, 'r') as file:
        for line in file:
            logs.append(line.strip())
    return logs

# Function to normalize logs
def normalize_log(log_line):
    normalized_log = {
        "timestamp": log_line.split()[0],
        "source": log_line.split()[1],
        "message": " ".join(log_line.split()[2:])
    }
    return normalized_log

def normalize_logs(logs):
    normalized_logs = []
    for log in logs:
        normalized_logs.append(normalize_log(log))
    return normalized_logs

# Function to correlate events and update firewall
def correlate_events_and_update_firewall(normalized_logs):
    correlated_events = []
    for log in normalized_logs:
        # Example correlation rule: Detect multiple failed login attempts
        if "failed login" in log['message']:
            event = {
                "timestamp": log['timestamp'],
                "event": "Failed Login Attempt",
                "details": log['message'],
                "source_ip": log['source']
            }
            correlated_events.append(event)
            update_firewall(log['source'], "block")
            send_alert(event)
    return correlated_events

# Function to update firewall
def update_firewall(ip_address, action):
    if action == "block":
        command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
        os.system(command)
        logger.info(f"Blocked IP address: {ip_address}")

# Function to send alert
def send_alert(event):
    msg = MIMEText(f"Alert: {event['event']} detected at {event['timestamp']}\nDetails: {event['details']}")
    msg['Subject'] = f"Security Alert: {event['event']}"
    msg['From'] = 'siem@example.com'
    msg['To'] = 'admin@example.com'

    with smtplib.SMTP('localhost') as server:
        server.sendmail(msg['From'], [msg['To']], msg.as_string())

# Collect, normalize, and correlate logs
logs = collect_logs()
normalized_logs = normalize_logs(logs)
correlated_events = correlate_events_and_update_firewall(normalized_logs)

# Store results for further analysis
with open('correlated_events.json', 'w') as outfile:
    json.dump(correlated_events, outfile)