
import os
import hashlib
import time
import psutil
from scapy.all import sniff

# Monitor for high CPU usage
def monitor_processes():
    print("Monitoring processes for high CPU usage...")
    cpu_usage = psutil.cpu_percent(interval=1)
    if cpu_usage > 80:  # Example threshold
        print("Alert: High CPU usage detected!")
    else:
        print("No unusual activity found.")

# Calculate and compare file hash for integrity checking
def get_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
        return hashlib.sha256(file_content).hexdigest()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def monitor_file_integrity():
    print("Checking for any changes in file integrity...")
    file_paths_to_monitor = ['test_file1.txt', 'test_file2.txt']
    baseline_hashes = {path: get_file_hash(path) for path in file_paths_to_monitor}

    time.sleep(1)  # Simulate some delay
    for path, baseline_hash in baseline_hashes.items():
        if baseline_hash:
            current_hash = get_file_hash(path)
            if current_hash == baseline_hash:
                print(f"No change detected in {path}. Integrity is valid.")
            else:
                print(f"Alert: File integrity compromised for {path}!")

# Monitor network traffic for suspicious connections
suspicious_connections_detected = False  # Track if any suspicious connections are found

def packet_callback(packet):
    global suspicious_connections_detected
    # Example criteria for suspicious network traffic
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Checking network traffic from {src_ip} to {dst_ip}...")
        if src_ip.startswith("34.") or dst_ip.startswith("34."):
            print(f"Alert: Suspicious network connection from {src_ip} to {dst_ip}")
            suspicious_connections_detected = True

def monitor_network():
    print("Monitoring network traffic for suspicious connections...")
    try:
        sniff(filter="ip", prn=packet_callback, timeout=10, store=0)  # Adjust timeout for demonstration
        if not suspicious_connections_detected:
            print("No suspicious connections found.")
    except PermissionError:
        print("Error: Network monitoring requires administrative privileges.")

# Main function
def main():
    print("Starting EDR System...\n")

    # Step 1: Monitor processes
    monitor_processes()

    # Step 2: Monitor file integrity
    monitor_file_integrity()

    # Step 3: Monitor network traffic
    monitor_network()

    # Final status
    print("\nEndpoint is safe.")

# Entry point
if __name__ == "__main__":
    main()
