from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time

# Dictionary to track scan counts and timestamps
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Duration to block an IP (10 minutes)
BLOCK_DURATION = timedelta(minutes=10)

# List of common ports that we'll respond to (can be expanded)
COMMON_PORTS = list(range(1, 1001)) + [1433, 1521, 1723, 2049, 3306, 3389, 
                                     5432, 5900, 6379, 8080, 8443, 8888]

# Target IP to monitor
TARGET_IP = "157.230.88.84"

def is_ip_blocked(ip):
    """Check if the IP is already blocked in iptables."""
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
    return ip in result.stdout

def block_ip(ip):
    """Block the given IP using iptables."""
    if is_ip_blocked(ip):
        print(f"IP {ip} is already blocked. Skipping...")
        return

    print(f"Blocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    """Unblock the given IP."""
    print(f"Unblocking IP: {ip}")
    try:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")

def handle_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        if src_ip != TARGET_IP:
            return
            
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport

        # For SYN scans (Nmap default)
        if packet[TCP].flags == "S":
            print(f"SYN scan detected on port {dst_port} from {src_ip}")

            # Check and update scan count
            current_time = datetime.now()
            if scan_tracker[src_ip]["timestamp"] and current_time - scan_tracker[src_ip]["timestamp"] > BLOCK_DURATION:
                # Reset tracker after block duration
                scan_tracker[src_ip] = {"count": 0, "timestamp": None}

            scan_tracker[src_ip]["count"] += 1
            scan_tracker[src_ip]["timestamp"] = current_time

            if scan_tracker[src_ip]["count"] > 5:
                print(f"IP {src_ip} exceeded scan limit, blocking for 10 minutes...")
                block_ip(src_ip)
                # Schedule unblock
                unblock_time = datetime.now() + BLOCK_DURATION
                print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
                sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
                return

            # Respond with SYN-ACK to make port appear open
            syn_ack = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=dst_port, dport=src_port, flags="SA", seq=1000, ack=packet[TCP].seq + 1)
            )
            send(syn_ack, verbose=0)
            print(f"Sent SYN-ACK to {src_ip} on port {dst_port} - port appears open")

        # For ACK scans (Nmap -sA)
        elif packet[TCP].flags == "A":
            print(f"ACK scan detected on port {dst_port} from {src_ip}")
            # Respond with RST to make port appear unfiltered
            rst = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=dst_port, dport=src_port, flags="R", seq=0, ack=packet[TCP].seq + 1)
            )
            send(rst, verbose=0)
            print(f"Sent RST to {src_ip} on port {dst_port} - port appears unfiltered")

        # For NULL, FIN, XMAS scans (Nmap -sN, -sF, -sX)
        elif packet[TCP].flags in ["F", "N", "FPU"]:
            print(f"{packet[TCP].flags} scan detected on port {dst_port} from {src_ip}")
            # Respond with RST to make port appear closed
            rst = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=dst_port, dport=src_port, flags="R", seq=0, ack=0)
            )
            send(rst, verbose=0)
            print(f"Sent RST to {src_ip} on port {dst_port} - port appears closed")

    # For UDP scans (Nmap -sU)
    elif IP in packet and UDP in packet:
        src_ip = packet[IP].src
        if src_ip != TARGET_IP:
            return
            
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport
        
        print(f"UDP scan detected on port {dst_port} from {src_ip}")
        # For UDP, we can either ignore (shows as open|filtered) or respond (shows as open)
        # Here we choose to respond to make port appear open
        if dst_port in COMMON_PORTS:
            udp_response = (
                IP(dst=src_ip, src=packet[IP].dst) /
                UDP(sport=dst_port, dport=src_port) /
                Raw(load="Try harder!")
            )
            send(udp_response, verbose=0)
            print(f"Sent UDP response to {src_ip} on port {dst_port} - port appears open")

def unblock_expired_ips():
    """Unblock IPs whose block duration has expired."""
    now = datetime.now()
    for task in list(sniff_thread.unblock_tasks):
        if now >= task["unblock_time"]:
            unblock_ip(task["ip"])
            sniff_thread.unblock_tasks.remove(task)

class SniffThread:
    def __init__(self):
        self.unblock_tasks = []

    def start_sniffing(self):
        # Capture both TCP and UDP packets
        sniff(filter="tcp or udp", prn=handle_packet, store=0)

sniff_thread = SniffThread()

if __name__ == "__main__":
    # Start the sniffing in a separate thread
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)
    sniff_thread_thread.start()

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping...")