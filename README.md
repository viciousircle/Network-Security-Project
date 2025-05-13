# Network Security Project

# honeypot-waf-project

First, run the command line below:

`pip install -r requirements.txt`

---

sudo apt update
sudo apt install -y python3-pip tcpdump iptables-persistent

1. Initial

# Cài đặt các gói hệ thống cần thiết

sudo apt update
sudo apt install python3-venv python3-pip -y

python3 -m venv scapy-env
source scapy-env/bin/activate

pip install scapy
pip install python-iptables

# Tạo cấu trúc thư mục config và log

sudo mkdir -p /etc/syn_scan_detector
sudo mkdir -p /var/log/syn_scan_detector

(file chính)
nano syn_scan_detector.py

(sửa file)
rm syn_scan_detector.py

2. Vào lần 2

# Kích hoạt virtual environment

source scapy-env/bin/activate

python3 syn_scan_detector.py --interface eth0 --threshold 3 --block-minutes 1

python3 syn_scan_detector.py

python3 syn_scan_detector.py --interface eth0

A
source ~/attack_env/bin/activate

(A)

# Thực hiện các kiểu scan thử nghiệm

1.  SYN Scan với Nmap:
    sudo nmap -sS -Pn <target-ip>
    sudo nmap -sS -Pn 161.35.120.153

    nmap -T2 161.35.120.153
    nmap 161.35.120.153

        sudo tcpdump -i any -nn -v 'host <target_IP>'
        sudo tcpdump -i any -nn -v 'host 161.35.120.153'

        tcpdump -i any src host 161.35.120.153 -X

---

sudo python3 /root/firewall_cowrie.py
sudo nano /root/firewall_cowrie.py
rm /root/firewall_cowrie.py

---

1. log in vao admin user
2. log in vào attacker

---

bật cowrie
và
bật firewall
bật log cowrie

---

attacker nmap vào target ip
attacker nhận được thông tin có cổng mở
attacker tấn công vào ip address

---

nhận được các thông tin của log, xong phân tích đưa ra phản ứng sớm.

python3 -m venv cowrie-env
source cowrie-env/bin/activate
