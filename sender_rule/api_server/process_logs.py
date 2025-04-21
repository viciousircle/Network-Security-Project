import json
import pandas as pd
from collections import defaultdict
from datetime import datetime
from tabulate import tabulate


# ====== ⚙️ Cài đặt cấu hình ====== #
FAILED_LOGIN_THRESHOLD = 2
MALICIOUS_COMMANDS = ['wget', 'curl', 'nc', 'nmap', 'chmod', './']
LOG_FILE_PATH = "sender_rule/logs/received_logs.json"  # sửa theo đường dẫn của bạn

# ====== 🧠 Hàm xác định loại hình tấn công ====== #
def detect_attack_type(log):
    if log["eventid"] == "cowrie.login.failed":
        return "Brute-force login"
    elif log["eventid"] == "cowrie.command.input":
        cmd = log.get("input", "")
        for m in MALICIOUS_COMMANDS:
            if m in cmd:
                return f"Malware execution (cmd: {cmd})"
        return "Command execution"
    else:
        return "Unknown activity"

# ====== 📥 Đọc log JSON ====== #
with open(LOG_FILE_PATH, "r") as f:
    logs = json.load(f)

# ====== 🧼 Tiền xử lý & phân tích ====== #
parsed_logs = []
failed_logins = defaultdict(int)

for log in logs:
    ip = log.get("src_ip", "unknown")
    timestamp = log.get("timestamp")
    eventid = log.get("eventid", "unknown")
    attack_type = detect_attack_type(log)
    
    if eventid == "cowrie.login.failed":
        failed_logins[ip] += 1

    parsed_logs.append({
        "timestamp": timestamp,
        "src_ip": ip,
        "eventid": eventid,
        "attack_type": attack_type,
    })

# ====== 📊 Tạo DataFrame ====== #
df = pd.DataFrame(parsed_logs)

# Thêm cột 'suspected_bruteforce'
df["failed_login_count"] = df["src_ip"].map(lambda ip: failed_logins[ip])
df["suspected_bruteforce"] = df["failed_login_count"] >= FAILED_LOGIN_THRESHOLD

# ====== 📤 Xuất kết quả ====== #
print("\n📄 [BẢNG PHÂN TÍCH LOG - DẠNG BẢNG PANDAS]\n")
# print(df.sort_values(by=["src_ip", "timestamp"]).to_string(index=False))

df_sorted = df.sort_values(by=["src_ip", "timestamp"])
print(tabulate(df_sorted, headers='keys', tablefmt='grid', showindex=False))

# ====== 📢 Cảnh báo tấn công nghi vấn ====== #
print("\n🚨 [TỔNG HỢP CẢNH BÁO]\n")

suspicious_ips = df[df["suspected_bruteforce"]]["src_ip"].unique()

if len(suspicious_ips) == 0:
    print("✅ Không phát hiện IP nào có dấu hiệu brute-force.")
else:
    for ip in suspicious_ips:
        count = failed_logins[ip]
        print(f"⚠️ IP: {ip} nghi ngờ Brute-force ({count} lần login thất bại)")
