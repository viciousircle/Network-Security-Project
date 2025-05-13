from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
import time

# Dictionary to track scan counts and timestamps
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# Duration to block an IP (10 minutes)
BLOCK_DURATION = timedelta(minutes=10)

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

def unblock_expired_ips(sniff_thread):
    """Unblock IPs whose block duration has expired."""
    now = datetime.now()
    for task in list(sniff_thread.unblock_tasks):
        if now >= task["unblock_time"]:
            unblock_ip(task["ip"])
            sniff_thread.unblock_tasks.remove(task)

class SniffThread:
    def __init__(self):
        self.unblock_tasks = []

    def start_sniffing(self, handle_packet):
        sniff(filter="tcp", prn=handle_packet)
