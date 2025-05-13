#!/usr/bin/env python3
from scapy.all import *
from collections import defaultdict
from datetime import datetime, timedelta
import threading
import time
import random
import logging
from logging.handlers import RotatingFileHandler
import json
import os
import argparse
import ipaddress
import subprocess
import socket
import paramiko
from io import StringIO

def setup_logging():
    logger = logging.getLogger('syn_scan_detector')
    logger.setLevel(logging.INFO)
    
    os.makedirs('/var/log/syn_scan_detector', exist_ok=True)
    
    file_handler = RotatingFileHandler(
        '/var/log/syn_scan_detector/detector.log',
        maxBytes=5*1024*1024,
        backupCount=3
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger

logger = setup_logging()

class Config:
    def __init__(self):
        self.config = {
            'block_duration': timedelta(minutes=30),
            'scan_threshold': 5,
            'whitelist': ['127.0.0.1', '192.168.1.0/24'],
            'interface': None,
            'iptables_chain': 'INPUT',
            'cowrie_ports': [22, 23, 2222],  # Common Cowrie ports
            'honeypot_enabled': True,
            'honeypot_ip': None,  # Set to your Cowrie instance IP
            'fake_services': {
                'http': "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Welcome to our system!</h1></body></html>",
                'ftp': "220 FTP Server Ready\r\n",
                'smtp': "220 mail.example.com ESMTP Postfix\r\n"
            },
            'ssh_banner': "SSH-2.0-OpenSSH_7.9p1 Ubuntu-10ubuntu2.1",
            'fake_credentials': [
                ('admin', 'password123'),
                ('root', 'toor'),
                ('user', '123456')
            ]
        }
        self.load_config()
    
    def load_config(self):
        try:
            with open('/etc/syn_scan_detector/config.json') as f:
                file_config = json.load(f)
                self.config.update(file_config)
                self.config['block_duration'] = timedelta(
                    minutes=file_config.get('block_minutes', 30)
                )
                # Ensure honeypot_ip is set if honeypot is enabled
                if self.config['honeypot_enabled'] and not self.config['honeypot_ip']:
                    self.config['honeypot_ip'] = file_config.get('honeypot_ip', None)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Config load error: {str(e)}. Using defaults.")
    
    def reload_config(self):
        self.load_config()
        logger.info("Configuration reloaded")

config = Config()

class BlockManager:
    def __init__(self):
        self.scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None, "ports": set()})
        self.blocked_ips = set()
        self.lock = threading.Lock()
        self.iptables = IPTablesManager()
        self.honeypot_connections = {}
    
    def is_ip_blocked(self, ip):
        with self.lock:
            return ip in self.blocked_ips
    
    def block_ip(self, ip):
        if self.is_ip_blocked(ip):
            logger.info(f"IP {ip} is already blocked")
            return False
        
        if any(self._is_ip_in_network(ip, network) for network in config.config['whitelist']):
            logger.info(f"IP {ip} is in whitelist, skipping block")
            return False
        
        with self.lock:
            try:
                self.iptables.block(ip)
                self.blocked_ips.add(ip)
                logger.warning(f"Successfully blocked IP: {ip}")
                
                # Redirect blocked IP to honeypot if enabled
                if config.config['honeypot_enabled'] and config.config['honeypot_ip']:
                    self.redirect_to_honeypot(ip)
                
                return True
            except Exception as e:
                logger.error(f"Error blocking IP {ip}: {str(e)}")
                return False
    
    def redirect_to_honeypot(self, ip):
        """Redirect traffic from blocked IP to honeypot"""
        try:
            for port in config.config['cowrie_ports']:
                subprocess.run([
                    'iptables', '-t', 'nat', '-A', 'PREROUTING', 
                    '-s', ip, '-p', 'tcp', 
                    '--dport', str(port), 
                    '-j', 'DNAT', 
                    '--to-destination', f"{config.config['honeypot_ip']}:{port}"
                ], check=True)
            logger.info(f"Redirected {ip} to honeypot at {config.config['honeypot_ip']}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to redirect {ip} to honeypot: {str(e)}")
    
    def unblock_ip(self, ip):
        with self.lock:
            if ip not in self.blocked_ips:
                return
            
            try:
                # Remove honeypot redirection first
                if config.config['honeypot_enabled'] and config.config['honeypot_ip']:
                    self.remove_honeypot_redirection(ip)
                
                self.iptables.unblock(ip)
                self.blocked_ips.remove(ip)
                logger.info(f"Successfully unblocked IP: {ip}")
            except Exception as e:
                logger.error(f"Error unblocking IP {ip}: {str(e)}")
    
    def remove_honeypot_redirection(self, ip):
        """Remove honeypot redirection rules for an IP"""
        try:
            for port in config.config['cowrie_ports']:
                subprocess.run([
                    'iptables', '-t', 'nat', '-D', 'PREROUTING', 
                    '-s', ip, '-p', 'tcp', 
                    '--dport', str(port), 
                    '-j', 'DNAT', 
                    '--to-destination', f"{config.config['honeypot_ip']}:{port}"
                ], check=True)
            logger.info(f"Removed honeypot redirection for {ip}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove honeypot redirection for {ip}: {str(e)}")
    
    def _is_ip_in_network(self, ip, network):
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)

class IPTablesManager:
    def __init__(self):
        try:
            import iptc
            self.iptc = iptc
        except ImportError:
            logger.error("python-iptables not installed. Falling back to subprocess.")
            self.iptc = None
    
    def block(self, ip):
        if self.iptc:
            self._block_with_iptc(ip)
        else:
            self._block_with_subprocess(ip)
    
    def unblock(self, ip):
        if self.iptc:
            self._unblock_with_iptc(ip)
        else:
            self._unblock_with_subprocess(ip)
    
    def _block_with_iptc(self, ip):
        chain = self.iptc.Chain(self.iptc.Table(self.iptc.Table.FILTER), config.config['iptables_chain'])
        rule = self.iptc.Rule()
        rule.src = ip
        rule.target = self.iptc.Target(rule, "DROP")
        chain.insert_rule(rule)
    
    def _unblock_with_iptc(self, ip):
        chain = self.iptc.Chain(self.iptc.Table(self.iptc.Table.FILTER), config.config['iptables_chain'])
        for rule in chain.rules:
            if rule.src == ip and rule.target.name == "DROP":
                chain.delete_rule(rule)
    
    def _block_with_subprocess(self, ip):
        subprocess.run(
            ["iptables", "-A", config.config['iptables_chain'], "-s", ip, "-j", "DROP"],
            check=True
        )
    
    def _unblock_with_subprocess(self, ip):
        subprocess.run(
            ["iptables", "-D", config.config['iptables_chain'], "-s", ip, "-j", "DROP"],
            check=True
        )

class HoneypotService(threading.Thread):
    """Thread to handle fake services for detected scanners"""
    def __init__(self, ip, port, block_manager):
        super().__init__(daemon=True)
        self.ip = ip
        self.port = port
        self.block_manager = block_manager
        self.running = True
    
    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', self.port))
                s.listen(1)
                logger.info(f"Fake service started on port {self.port} for {self.ip}")
                
                while self.running:
                    conn, addr = s.accept()
                    if addr[0] == self.ip:
                        self.handle_connection(conn, addr)
                    else:
                        conn.close()
        except Exception as e:
            logger.error(f"Error in honeypot service on port {self.port}: {str(e)}")
    
    def handle_connection(self, conn, addr):
        try:
            logger.info(f"New connection from {addr[0]}:{addr[1]} to fake service on port {self.port}")
            
            if self.port == 22:  # SSH
                self.handle_ssh(conn)
            elif self.port == 23:  # Telnet
                self.handle_telnet(conn)
            elif self.port == 80:  # HTTP
                self.handle_http(conn)
            elif self.port == 21:  # FTP
                self.handle_ftp(conn)
            elif self.port == 25:  # SMTP
                self.handle_smtp(conn)
            else:
                conn.send(b"Welcome to our system!\n")
            
            conn.close()
        except Exception as e:
            logger.error(f"Error handling connection: {str(e)}")
            try:
                conn.close()
            except:
                pass
    
    def handle_ssh(self, conn):
        """Fake SSH server with paramiko"""
        try:
            transport = paramiko.Transport(conn)
            transport.local_version = config.config['ssh_banner']
            transport.add_server_key(paramiko.RSAKey.generate(2048))
            
            server = FakeSSHServer()
            transport.start_server(server=server)
            
            channel = transport.accept(20)
            if channel:
                channel.send("Welcome to our system!\n")
                channel.send("Login with username/password\n")
                
                # Simulate authentication attempts
                for _ in range(3):
                    channel.send("Username: ")
                    username = channel.recv(1024).decode().strip()
                    channel.send("Password: ")
                    password = channel.recv(1024).decode().strip()
                    
                    # Log the attempt
                    logger.info(f"SSH login attempt: {username}/{password} from {self.ip}")
                    
                    # Randomly accept or reject
                    if random.random() < 0.3:  # 30% chance of "success"
                        channel.send("\nAccess granted! But not really...\n")
                        time.sleep(5)
                        channel.send("Connection closed by remote host.\n")
                        break
                    else:
                        channel.send("\nAccess denied. Try again.\n")
                
                channel.close()
            transport.close()
        except Exception as e:
            logger.error(f"SSH handler error: {str(e)}")
    
    def handle_telnet(self, conn):
        """Fake Telnet server"""
        conn.send(b"Welcome to Telnet Server\n")
        conn.send(b"login: ")
        username = conn.recv(1024).strip()
        conn.send(b"password: ")
        password = conn.recv(1024).strip()
        
        logger.info(f"Telnet login attempt: {username.decode()}/{password.decode()} from {self.ip}")
        conn.send(b"\nLogin incorrect\n")
        time.sleep(2)
        conn.send(b"Connection closed by foreign host.\n")
    
    def handle_http(self, conn):
        """Fake HTTP server"""
        conn.send(config.config['fake_services']['http'].encode())
        logger.info(f"HTTP request from {self.ip}")
    
    def handle_ftp(self, conn):
        """Fake FTP server"""
        conn.send(config.config['fake_services']['ftp'].encode())
        logger.info(f"FTP connection from {self.ip}")
    
    def handle_smtp(self, conn):
        """Fake SMTP server"""
        conn.send(config.config['fake_services']['smtp'].encode())
        logger.info(f"SMTP connection from {self.ip}")

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
    
    def check_auth_password(self, username, password):
        # Always return AUTH_FAILED to keep them trying
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        return 'password'
    
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

class PacketHandler:
    def __init__(self, block_manager):
        self.block_manager = block_manager
        self.active_honeypots = {}
    
    def handle_packet(self, packet):
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
        
        # Skip non-SYN packets and whitelisted IPs
        if packet[TCP].flags != "S" or any(
            self.block_manager._is_ip_in_network(src_ip, network) 
            for network in config.config['whitelist']
        ):
            return
        
        logger.info(f"SYN packet detected from {src_ip} to port {dst_port}")
        
        current_time = datetime.now()
        
        # Track scan attempts
        with self.block_manager.lock:
            tracker = self.block_manager.scan_tracker[src_ip]
            
            # Reset if past block duration
            if tracker["timestamp"] and current_time - tracker["timestamp"] > config.config['block_duration']:
                tracker["count"] = 0
                tracker["ports"].clear()
                tracker["timestamp"] = None
            
            tracker["count"] += 1
            tracker["ports"].add(dst_port)
            tracker["timestamp"] = current_time
            
            # Check if threshold exceeded
            if tracker["count"] >= config.config['scan_threshold']:
                logger.warning(f"IP {src_ip} exceeded scan threshold ({config.config['scan_threshold']}), blocking...")
                if self.block_manager.block_ip(src_ip):
                    unblock_time = current_time + config.config['block_duration']
                    SnifferThread.unblock_tasks.append({
                        "ip": src_ip,
                        "unblock_time": unblock_time
                    })
                    logger.info(f"IP {src_ip} will be unblocked at {unblock_time}")
                    
                    # Start fake services if not already running
                    if config.config['honeypot_enabled']:
                        self.start_fake_services(src_ip, tracker["ports"])
        
        # Send response based on port
        if dst_port in config.config['cowrie_ports']:
            self.handle_cowrie_port(packet, src_ip, dst_port, src_port)
        elif dst_port in [80, 21, 25, 23]:  # Common services
            self.handle_common_service(packet, src_ip, dst_port, src_port)
        else:
            self.send_syn_ack(packet, src_ip, dst_port, src_port)
    
    def start_fake_services(self, ip, ports):
        """Start fake services for the attacker"""
        with self.block_manager.lock:
            if ip in self.active_honeypots:
                return
            
            self.active_honeypots[ip] = []
            
            for port in ports:
                if port in [22, 23, 80, 21, 25]:  # Only start services we can fake
                    service = HoneypotService(ip, port, self.block_manager)
                    service.start()
                    self.active_honeypots[ip].append(service)
                    logger.info(f"Started fake service on port {port} for {ip}")
    
    def stop_fake_services(self, ip):
        """Stop fake services when IP is unblocked"""
        with self.block_manager.lock:
            if ip in self.active_honeypots:
                for service in self.active_honeypots[ip]:
                    service.running = False
                del self.active_honeypots[ip]
                logger.info(f"Stopped fake services for {ip}")
    
    def handle_cowrie_port(self, packet, src_ip, dst_port, src_port):
        """Handle ports that should go to Cowrie honeypot"""
        if config.config['honeypot_enabled'] and config.config['honeypot_ip']:
            # Send SYN-ACK to complete handshake
            self.send_syn_ack(packet, src_ip, dst_port, src_port)
            
            # For SSH, we can start a fake SSH server if not redirecting to Cowrie
            if dst_port == 22 and not config.config['honeypot_ip']:
                self.start_fake_ssh(packet, src_ip, dst_port, src_port)
        else:
            self.send_syn_ack(packet, src_ip, dst_port, src_port)
    
    def handle_common_service(self, packet, src_ip, dst_port, src_port):
        """Handle common services with fake responses"""
        self.send_syn_ack(packet, src_ip, dst_port, src_port)
        
        # Send fake service banner if configured
        if dst_port == 80 and 'http' in config.config['fake_services']:
            self.send_fake_http(packet, src_ip, src_port)
        elif dst_port == 21 and 'ftp' in config.config['fake_services']:
            self.send_fake_ftp(packet, src_ip, src_port)
        elif dst_port == 25 and 'smtp' in config.config['fake_services']:
            self.send_fake_smtp(packet, src_ip, src_port)
        elif dst_port == 23 and 'telnet' in config.config['fake_services']:
            self.send_fake_telnet(packet, src_ip, src_port)
    
    def send_syn_ack(self, packet, src_ip, dst_port, src_port):
        try:
            seq_num = random.randint(1000, 999999)
            syn_ack = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=dst_port, dport=src_port, flags="SA", 
                   seq=seq_num, ack=packet[TCP].seq + 1)
            )
            send(syn_ack, verbose=0, iface=config.config['interface'])
            logger.debug(f"SYN-ACK sent to {src_ip}:{src_port}")
        except Exception as e:
            logger.error(f"Error sending SYN-ACK: {str(e)}")
    
    def send_fake_http(self, packet, src_ip, src_port):
        try:
            ack_packet = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=80, dport=src_port, flags="PA", 
                   seq=random.randint(1000, 999999), 
                   ack=packet[TCP].seq + 1) /
                Raw(load=config.config['fake_services']['http'])
            )
            send(ack_packet, verbose=0)
            logger.info(f"Sent fake HTTP response to {src_ip}")
        except Exception as e:
            logger.error(f"Error sending fake HTTP: {str(e)}")
    
    def send_fake_ftp(self, packet, src_ip, src_port):
        try:
            ack_packet = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=21, dport=src_port, flags="PA", 
                   seq=random.randint(1000, 999999), 
                   ack=packet[TCP].seq + 1) /
                Raw(load=config.config['fake_services']['ftp'])
            )
            send(ack_packet, verbose=0)
            logger.info(f"Sent fake FTP response to {src_ip}")
        except Exception as e:
            logger.error(f"Error sending fake FTP: {str(e)}")
    
    def send_fake_smtp(self, packet, src_ip, src_port):
        try:
            ack_packet = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=25, dport=src_port, flags="PA", 
                   seq=random.randint(1000, 999999), 
                   ack=packet[TCP].seq + 1) /
                Raw(load=config.config['fake_services']['smtp'])
            )
            send(ack_packet, verbose=0)
            logger.info(f"Sent fake SMTP response to {src_ip}")
        except Exception as e:
            logger.error(f"Error sending fake SMTP: {str(e)}")
    
    def send_fake_telnet(self, packet, src_ip, src_port):
        try:
            ack_packet = (
                IP(dst=src_ip, src=packet[IP].dst) /
                TCP(sport=23, dport=src_port, flags="PA", 
                   seq=random.randint(1000, 999999), 
                   ack=packet[TCP].seq + 1) /
                Raw(load="Welcome to Telnet Server\nlogin: ")
            )
            send(ack_packet, verbose=0)
            logger.info(f"Sent fake Telnet response to {src_ip}")
        except Exception as e:
            logger.error(f"Error sending fake Telnet: {str(e)}")

class SnifferThread:
    unblock_tasks = []
    
    def __init__(self, block_manager):
        self.block_manager = block_manager
        self.packet_handler = PacketHandler(block_manager)
        self.stop_sniff = False
    
    def start_sniffing(self):
        sniff_filter = "tcp"
        if config.config['interface']:
            sniff(iface=config.config['interface'], filter=sniff_filter, 
                 prn=self.packet_handler.handle_packet, store=False,
                 stop_filter=lambda x: self.stop_sniff)
        else:
            sniff(filter=sniff_filter, prn=self.packet_handler.handle_packet, 
                 store=False, stop_filter=lambda x: self.stop_sniff)

class UnblockThread(threading.Thread):
    def __init__(self, block_manager):
        super().__init__(daemon=True)
        self.block_manager = block_manager
        self.packet_handler = PacketHandler(block_manager)
    
    def run(self):
        while True:
            self.unblock_expired_ips()
            time.sleep(5)
    
    def unblock_expired_ips(self):
        now = datetime.now()
        for task in list(SnifferThread.unblock_tasks):
            if now >= task["unblock_time"]:
                self.block_manager.unblock_ip(task["ip"])
                self.packet_handler.stop_fake_services(task["ip"])
                SnifferThread.unblock_tasks.remove(task)

def main():
    parser = argparse.ArgumentParser(description='SYN Scan Detector and Honeypot Redirector')
    parser.add_argument('--interface', help='Network interface to sniff on')
    parser.add_argument('--threshold', type=int, help='Scan threshold before blocking')
    parser.add_argument('--block-minutes', type=int, help='Minutes to block IP')
    parser.add_argument('--honeypot-ip', help='Cowrie honeypot IP address')
    parser.add_argument('--no-honeypot', action='store_true', help='Disable honeypot features')
    args = parser.parse_args()
    
    # Update config from command line
    if args.interface:
        config.config['interface'] = args.interface
    if args.threshold:
        config.config['scan_threshold'] = args.threshold
    if args.block_minutes:
        config.config['block_duration'] = timedelta(minutes=args.block_minutes)
    if args.honeypot_ip:
        config.config['honeypot_ip'] = args.honeypot_ip
    if args.no_honeypot:
        config.config['honeypot_enabled'] = False
    
    logger.info("Starting Enhanced SYN Scan Detector with Honeypot Integration")
    logger.info(f"Configuration: {json.dumps(config.config, default=str)}")
    
    # Check if we can redirect to honeypot
    if config.config['honeypot_enabled'] and not config.config['honeypot_ip']:
        logger.warning("Honeypot enabled but no honeypot_ip specified in config!")
    
    block_manager = BlockManager()
    sniffer = SnifferThread(block_manager)
    unblocker = UnblockThread(block_manager)
    
    # Start threads
    sniff_thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
    sniff_thread.start()
    unblocker.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sniffer.stop_sniff = True
        
        # Cleanup
        for ip in list(block_manager.blocked_ips):
            block_manager.unblock_ip(ip)
            sniffer.packet_handler.stop_fake_services(ip)
        
        logger.info("Cleanup completed. Goodbye!")

if __name__ == "__main__":
    main()