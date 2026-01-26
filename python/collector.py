import socket
import csv

HOST = '127.0.0.1'
PORT = 7777
DATASET_FILE = 'dataset.csv'

def arp_collector():
    """
    Create a new .csv file, establish connection to C sniffer and collect data sended by the sniffer.
    This allows the future model to learn common network traffic and detect any anomalies.
    That's all :)
    """
    with open(DATASET_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "mac", "ip"])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    print(f"[*] Collector listening on {HOST}:{PORT}. (Be sure that the sniffer is running.)")
    conn, addr = server.accept()
    print(f"[*] Connected: {addr}. Populating...")

    buffer = ""
    try:
        while True:
            chunk = conn.recv(1024).decode('utf-8', errors='ignore')
            if not chunk: break
            buffer += chunk

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line:
                    parts = line.strip().split(',')
                    if len(parts) == 3:
                        with open(DATASET_FILE, 'a', newline='') as f:
                            csv.writer(f).writerow(parts)
                            print(f"REC: {parts}", end='\r')
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
    finally:
        conn.close()


if __name__ == "__main__":
    arp_collector()
