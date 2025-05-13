import threading
import time
from firewall import SniffThread, unblock_expired_ips
from cowrie import handle_packet

if __name__ == "__main__":
    # Initialize sniff thread
    sniff_thread = SniffThread()

    # Start the sniffing in a separate thread
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, args=(handle_packet,), daemon=True)
    sniff_thread_thread.start()

    # Monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips(sniff_thread)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping...")
