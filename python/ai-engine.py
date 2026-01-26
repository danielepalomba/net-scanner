import socket
import joblib
import numpy as np
from collections import defaultdict
from colorama import Fore, Back, Style

HOST = '127.0.0.1'
PORT = 7777

"""
The trainer's logic is replicated
"""
global_window = []
device_states = defaultdict(lambda: {'last_ts': 0, 'count_window': []})
model = None


def load_model():
    global model
    try:
        model = joblib.load('model.pkl')
        print(Style.BRIGHT + Fore.BLACK + Back.GREEN + "Model loaded.")
    except:
        print(Style.BRIGHT + Fore.BLACK + Back.RED + "Could not load model.")
        exit()


def process_packet(mac, timestamp, is_trusted):
    global global_window

    # Global Frequency
    global_window = [t for t in global_window if t > timestamp - 60]
    global_window.append(timestamp)
    global_freq = len(global_window)

    # Local Features
    state = device_states[mac]

    if state['last_ts'] == 0:
        delta = 1.0
    else:
        delta = timestamp - state['last_ts']
        if delta == 0: delta = 0.01

    state['last_ts'] = timestamp

    state['count_window'] = [t for t in state['count_window'] if t > timestamp - 60]
    state['count_window'].append(timestamp)
    local_freq = len(state['count_window'])

    features = np.array([[delta, local_freq, global_freq]])

    try:
        # Anomaly = -1, Normal = 1
        prediction = model.predict(features)[0]
        score = model.decision_function(features)[0]

        """
        If the prediction = -1, it means that the model has detected anomalous behavior, 
        if the anomalous behavior is caused by a trusted device -> possible spoofing, 
        if instead the device is untrusted -> it means that someone is carrying out an attack.
        """
        confidence = -0.15
        if prediction == -1 and score < confidence:
            if is_trusted == 1:
                print(Style.BRIGHT + Fore.BLACK + Back.RED + f"\n[ALERT]")
                print(Fore.YELLOW + Back.BLACK + f"      Target: {mac} (Trusted device)")
                print(Fore.RED + f"      Anomaly: Freq={local_freq}/min, Global={global_freq}, Delta={delta:.3f}s")
                print(Fore.CYAN + f"      Score AI: {score:.3f}")
            else:
                print(Style.BRIGHT + Fore.BLACK + Back.RED + f"\n[ALERT]")
                print(Fore.YELLOW + Back.BLACK + f"      Source: {mac} (Not authorized)")
                print(Fore.RED + f"      Type: Flooding or scanning")
                print(Fore.CYAN + f"      Score AI: {score:.3f}")

        else:
            if is_trusted == 0:
                print(Style.BRIGHT + Fore.BLACK + Back.YELLOW + f"[INFO] New device: {mac}")
            else:
                # All good
                pass

    except Exception as e:
        print(Style.BRIGHT + Fore.BLACK + Back.RED + f"[ERR] Error: {e}")


def launch_server():
    load_model()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print(Style.BRIGHT + Fore.BLACK + Back.GREEN + f"[*] AI Engine listening on {HOST}:{PORT}...")

    conn, addr = server.accept()
    print(f"[*] Sniffer connected: {addr}")

    buffer = ""
    while True:
        try:
            chunk = conn.recv(1024).decode('utf-8', errors='ignore')
            if not chunk: break
            buffer += chunk

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if line:
                    try:
                        # CSV: TS, MAC, IP, TRUSTED
                        parts = line.split(',')
                        if len(parts) >= 4:
                            ts = int(parts[0])
                            mac = parts[1]
                            # ip = parts[2] # Not used anymore
                            is_trusted = int(parts[3])

                            process_packet(mac, ts, is_trusted)
                    except ValueError:
                        pass
        except KeyboardInterrupt:
            print(Style.BRIGHT + Fore.BLACK + Back.YELLOW + "\n[*] Shutdown.")
            break
        except ConnectionResetError:
            print(Style.BRIGHT + Fore.BLACK + Back.YELLOW + "[*] Net-Scanner disconnected.")
            break

    conn.close()


if __name__ == "__main__":
    launch_server()
