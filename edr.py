import os
import psutil
import hashlib
from scapy.all import sniff, IP
import json
from datetime import datetime

# Paths to monitor for file integrity
file_paths_to_monitor = ["test_file1.txt", "test_file2.txt"]

# Log file
log_file = "edr_logs.json"

def log_event(event_type, details):
    """
    Logs an event to a JSON log file.
    """
    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "details": details
    }
    with open(log_file, "a") as f:
        json.dump(event, f)
        f.write("\n")

def get_file_hash(file_path):
    """
    Calculates the SHA-256 hash of a given file.
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None

def monitor_processes():
    """
    Monitors system processes for high CPU usage.
    """
    for process in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):
        cpu_usage = process.info['cpu_percent']
        # Trigger alert if CPU usage exceeds 80%
        if cpu_usage > 80:
            log_event("Process Alert", {"pid": process.info['pid'], "name": process.info['name'], "cpu_usage": cpu_usage})
            print(f"Alert: High CPU usage detected in process {process.info['name']} (PID: {process.info['pid']})")

def monitor_file_integrity():
    """
    Monitors specified files for changes in integrity.
    Logs an alert if a file's hash doesn't match its baseline.
    """
    baseline_hashes = {path: get_file_hash(path) for path in file_paths_to_monitor if os.path.isfile(path)}

    for path in file_paths_to_monitor:
        if os.path.isfile(path):
            current_hash = get_file_hash(path)
            # Trigger alert if hash has changed
            if baseline_hashes.get(path) != current_hash:
                log_event("File Integrity Alert", {"file_path": path})
                print(f"Alert: File {path} has been modified!")

def monitor_network():
    """
    Monitors network traffic for suspicious activity.
    """
    def packet_callback(packet):
        # Example condition: Alert if a packet's destination IP matches a specific address
        if packet.haslayer(IP) and packet[IP].dst == "192.168.0.113":  # Replace with an actual suspicious IP
            log_event("Network Alert", {"src": packet[IP].src, "dst": packet[IP].dst})
            print(f"Alert: Suspicious network connection from {packet[IP].src} to {packet[IP].dst}")
    
    sniff(filter="tcp", prn=packet_callback, store=0, count=10, timeout=5)  # Limited capture for testing

def main():
    print("Starting EDR System...")
    monitor_processes()            # Monitor system processes
    monitor_file_integrity()        # Monitor file integrity
    monitor_network()               # Monitor network activity
    


if __name__ == "__main__":
    main()
