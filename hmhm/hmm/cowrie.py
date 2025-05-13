from scapy.all import *
from datetime import datetime
import subprocess

# Honeypot IP and Port (Cowrie Honeypot)
HONEYPOT_IP = "192.168.1.100"  # Địa chỉ IP của Cowrie
HONEYPOT_PORT = 2222           # Cổng mà Cowrie đang lắng nghe (cổng SSH giả)

def handle_packet(packet, sniff_thread):
    if TCP in packet and packet[TCP].flags == "S":  # SYN flag detected
        src_ip = packet[IP].src
        port = packet[TCP].dport
        src_port = packet[TCP].sport

        print(f"Scan detected on port {port} from {src_ip}")

        # Check and update scan count
        current_time = datetime.now()
        if sniff_thread.scan_tracker[src_ip]["timestamp"] and current_time - sniff_thread.scan_tracker[src_ip]["timestamp"] > timedelta(minutes=10):
            # Reset tracker after block duration
            sniff_thread.scan_tracker[src_ip] = {"count": 0, "timestamp": None}

        sniff_thread.scan_tracker[src_ip]["count"] += 1
        sniff_thread.scan_tracker[src_ip]["timestamp"] = current_time

        if sniff_thread.scan_tracker[src_ip]["count"] > 5:
            print(f"IP {src_ip} exceeded scan limit, blocking for 10 minutes...")
            block_ip(src_ip)
            # Redirect to Cowrie honeypot instead of sending 'try harder'
            print(f"Redirecting IP {src_ip} to Cowrie honeypot at {HONEYPOT_IP}:{HONEYPOT_PORT}")
            
            # Respond with SYN-ACK to start connection to honeypot
            syn_ack = (
                IP(dst=HONEYPOT_IP, src=src_ip) /
                TCP(sport=port, dport=HONEYPOT_PORT, flags="SA", seq=100, ack=packet[TCP].seq + 1)
            )
            send(syn_ack, verbose=0)
            print(f"Sent SYN-ACK to {src_ip}, redirecting to Cowrie honeypot.")

            # You can further simulate the session by sending data packets to Cowrie.
            data_packet = (
                IP(dst=HONEYPOT_IP, src=src_ip) /
                TCP(sport=port, dport=HONEYPOT_PORT, flags="PA", seq=101, ack=packet[TCP].seq + 1) /
                Raw(load="You're connected to a honeypot, try harder!")
            )
            send(data_packet, verbose=0)
            print(f"Sent data packet to Cowrie honeypot.")

            return

        # Respond with SYN-ACK
        syn_ack = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
        )
        send(syn_ack, verbose=0)
        print(f"Sent SYN-ACK to {src_ip} on port {port}")
