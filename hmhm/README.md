# SYN Scan Detector and IP Blocker

## Giới thiệu

Chương trình này là một công cụ phát hiện và ngăn chặn các cuộc tấn công SYN Scan bằng Firewall + Honeypot.

SYN Scan là một kỹ thuật quét cổng được sử dụng bởi các kẻ tấn công để phát hiện các cổng mở trên máy chủ mục tiêu bằng cách gửi các gói SYN mà không thiết lập kết nối TCP hoàn chỉnh.

Chương trình này sẽ phát hiện các gói SYN không hợp lệ và chặn các IP có hành vi quét quá mức.

## Các tính năng chính:

-   **Phát hiện SYN Scan**: Chương trình sẽ giám sát mạng và phát hiện các gói SYN bất thường.
-   **Chặn IP**: Nếu một IP vượt quá ngưỡng quét được cấu hình, chương trình sẽ chặn IP đó trong một khoảng thời gian nhất định.
-   **Gửi phản hồi SYN-ACK**: Chương trình gửi phản hồi SYN-ACK giả để làm cho các gói SYN không hợp lệ không gây hại.
-   **Gửi thông điệp troll**: Sau khi phát hiện một gói SYN bất hợp pháp, chương trình sẽ gửi một thông điệp troll đến IP của kẻ tấn công.

## Cấu hình

Các tham số cấu hình bao gồm:

-   **block_duration**: Thời gian chặn IP (mặc định 10 phút).
-   **scan_threshold**: Ngưỡng số lượng gói SYN gửi từ một IP trước khi bị chặn (mặc định 5).
-   **whitelist**: Danh sách các địa chỉ IP hoặc mạng con không bị chặn (mặc định `127.0.0.1`, `192.168.1.0/24`).
-   **interface**: Giao diện mạng cần giám sát (để trống nếu muốn giám sát tất cả giao diện).
-   **iptables_chain**: Chuỗi iptables để chặn IP (mặc định là `INPUT`).

# Phân tích và mô phỏng hoạt động của script SYN Scan Detector

Script này là một công cụ phát hiện và ngăn chặn SYN scan (một hình thức quét cổng) trong mạng. Dưới đây là mô phỏng những gì sẽ xảy ra khi chạy file này:

1. Khởi tạo ban đầu
   Khi chạy script (sudo python3 syn_scan_detector.py), các bước sau sẽ diễn ra:

Thiết lập logging:

Tạo thư mục /var/log/syn_scan_detector nếu chưa tồn tại

Thiết lập ghi log xoay vòng (5MB/file, tối đa 3 file)

Ghi log cả ra console và file

Đọc cấu hình:

Đọc file cấu hình /etc/syn_scan_detector/config.json nếu có

Nếu không có file cấu hình, sử dụng giá trị mặc định:

Thời gian block: 10 phút

Ngưỡng phát hiện scan: 5 gói SYN

Whitelist: 127.0.0.1 và 192.168.1.0/24

Chain iptables mặc định: INPUT

Khởi tạo các thành phần chính:

BlockManager: Quản lý IP bị block

IPTablesManager: Quản lý iptables để block/unblock IP

PacketHandler: Xử lý các gói tin mạng

SnifferThread: Bắt các gói tin mạng

UnblockThread: Tự động unblock IP sau thời gian quy định

2. Hoạt động chính
   Sau khi khởi động, hệ thống sẽ:

Bắt đầu sniffing network:

Lắng nghe trên interface mạng được chỉ định (hoặc tất cả interfaces nếu không chỉ định)

Chỉ lọc các gói tin TCP (tcp)

Khi phát hiện gói SYN:

Ghi log thông tin gói tin (IP nguồn, cổng đích)

Kiểm tra xem IP nguồn có trong whitelist không

Tăng bộ đếm scan cho IP đó

Nếu vượt quá ngưỡng (mặc định 5 gói SYN):

Thêm rule DROP vào iptables cho IP đó

Lên lịch unblock sau thời gian quy định (mặc định 10 phút)

Ghi log cảnh báo

Gửi phản hồi troll:

Gửi phản hồi SYN-ACK giả mạo

Gửi thêm gói tin chứa message "try harder"

Tự động unblock IP:

Mỗi 5 giây kiểm tra các IP bị block

Nếu đã hết thời gian block, xóa rule DROP trong iptables

Ghi log thông tin unblock

3. Ví dụ mô phỏng hoạt động
   Giả sử có một máy (IP: 192.168.1.100) thực hiện SYN scan đến server chạy script này:

Lần 1-4:

Máy gửi 4 gói SYN đến các cổng ngẫu nhiên

Script ghi log: SYN packet detected from 192.168.1.100 to port XXXX

Script gửi SYN-ACK giả và message "try harder"

Bộ đếm tăng lên 4 (chưa vượt ngưỡng)

Lần 5:

Máy gửi gói SYN thứ 5

Script phát hiện vượt ngưỡng (5 > 5)

Ghi log: IP 192.168.1.100 exceeded scan threshold (5), blocking...

Thêm rule iptables: iptables -A INPUT -s 192.168.1.100 -j DROP

Ghi log: Successfully blocked IP: 192.168.1.100

Lên lịch unblock sau 10 phút

Sau 10 phút:

UnblockThread kiểm tra và thấy đã đủ thời gian

Xóa rule iptables: iptables -D INPUT -s 192.168.1.100 -j DROP

Ghi log: Successfully unblocked IP: 192.168.1.100

4. Xử lý khi dừng script
   Khi nhấn Ctrl+C:

Ghi log: Shutting down...

Dọn dẹp tất cả các rule iptables đã tạo

Ghi log: Cleanup completed. Goodbye!

5. Các tính năng đặc biệt
   Whitelist: IP trong whitelist sẽ không bị block

Troll kẻ tấn công: Gửi phản hồi SYN-ACK giả và message "try harder"

Logging: Ghi log đầy đủ các sự kiện

Tự động unblock: Sau thời gian quy định

Hỗ trợ cả iptables và subprocess: Sử dụng python-iptables nếu có, nếu không dùng lệnh iptables trực tiếp

Script này hoạt động như một hệ thống phòng thủ chủ động, không chỉ phát hiện mà còn chủ động đánh lừa và chặn các nỗ lực quét cổng.
