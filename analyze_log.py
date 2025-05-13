import json
from collections import Counter, defaultdict
from tabulate import tabulate
import os

LOG_FILE = "/var/log/cowrie/cowrie.json"  # chỉnh lại nếu bạn lưu log ở nơi khác

def load_log(file_path):
    stats = {
        "ip_counter": Counter(),
        "usernames": Counter(),
        "passwords": Counter(),
        "downloads": Counter(),
        "commands": Counter(),
        "directories_accessed": Counter()
    }

    if not os.path.isfile(file_path):
        print(f"Không tìm thấy file log: {file_path}")
        return stats

    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entry = json.loads(line)
                ip = entry.get("src_ip")
                if ip:
                    stats["ip_counter"][ip] += 1

                eventid = entry.get("eventid")

                # Ghi nhận lệnh nhập
                if eventid == "cowrie.command.input":
                    stats["commands"][entry["input"]] += 1

                # Ghi nhận username/password
                if eventid == "cowrie.login.failed":
                    stats["usernames"][entry["username"]] += 1
                    stats["passwords"][entry["password"]] += 1

                # Ghi nhận download
                if eventid == "cowrie.session.file_download":
                    stats["downloads"][entry["url"]] += 1

                # Ghi nhận file/thư mục truy cập
                if eventid == "cowrie.fs.file_read" or eventid == "cowrie.fs.file_write":
                    stats["directories_accessed"][entry["filename"]] += 1

            except json.JSONDecodeError:
                continue

    return stats

def print_stats(stats):
    print("\n📊 Top IPs tấn công:")
    print(tabulate(stats['ip_counter'].most_common(10), headers=["IP", "Số sự kiện"], tablefmt="grid"))

    print("\n👤 Username bị thử nhiều:")
    print(tabulate(stats['usernames'].most_common(10), headers=["Username", "Lượt thử"], tablefmt="grid"))

    print("\n🔐 Password bị thử nhiều:")
    print(tabulate(stats['passwords'].most_common(10), headers=["Password", "Lượt thử"], tablefmt="grid"))

    print("\n🌐 URL tải file:")
    print(tabulate(stats['downloads'].most_common(5), headers=["URL", "Lượt tải"], tablefmt="grid"))

    print("\n💻 Lệnh được nhập:")
    print(tabulate(stats['commands'].most_common(10), headers=["Lệnh", "Số lần"], tablefmt="grid"))

    print("\n📁 File/thư mục bị truy cập:")
    print(tabulate(stats['directories_accessed'].most_common(10), headers=["File/Thư mục", "Số lần"], tablefmt="grid"))

if __name__ == "__main__":
    stats = load_log(LOG_FILE)
    print_stats(stats)