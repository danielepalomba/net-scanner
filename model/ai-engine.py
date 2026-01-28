import socket
import joblib
import numpy as np
import threading
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import queue
import time
from features import FeatureExtractor

HOST = '127.0.0.1'
PORT = 7777

class AIEngineGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Net-Scanner AI Engine")
        self.geometry("800x600")
        
        # UI Setup
        self.setup_ui()
        
        # Model & Logic
        self.model = None
        self.feature_extractor = FeatureExtractor()
        self.running = False
        self.log_queue = queue.Queue()
        
        # Load Model
        self.load_model()
        
        # Start Server Thread
        self.start_server()
        
        # Periodic GUI Update
        self.after(100, self.process_queue)

    def setup_ui(self):
        # Header
        header_frame = tk.Frame(self, bg="#2c3e50", height=50)
        header_frame.pack(fill=tk.X)
        header_label = tk.Label(header_frame, text="Net-Scanner AI Monitor", 
                                font=("Helvetica", 16, "bold"), bg="#2c3e50", fg="white")
        header_label.pack(pady=10)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Stopped")
        status_label = tk.Label(self, textvariable=self.status_var, relief=tk.SUNKEN, anchor="w")
        status_label.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Main Area
        main_frame = tk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Stats Panel
        stats_frame = tk.LabelFrame(main_frame, text="Statistics", padx=10, pady=10)
        stats_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))
        
        self.lbl_packets = tk.Label(stats_frame, text="Total Packets: 0", font=("Helvetica", 10))
        self.lbl_packets.pack(side=tk.LEFT, padx=20)
        
        self.lbl_anomalies = tk.Label(stats_frame, text="Anomalies Detected: 0", font=("Helvetica", 10), fg="red")
        self.lbl_anomalies.pack(side=tk.LEFT, padx=20)
        
        self.packet_count = 0
        self.anomaly_count = 0
        
        # Logs
        log_frame = tk.LabelFrame(main_frame, text="Event Log")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_area = scrolledtext.ScrolledText(log_frame, state='disabled', font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True)
        
        # Tags for coloring
        self.log_area.tag_config("INFO", foreground="green")
        self.log_area.tag_config("WARN", foreground="#f39c12")
        self.log_area.tag_config("ERR", foreground="red", background="#fadbd8")
        self.log_area.tag_config("NORMAL", foreground="black")

    def load_model(self):
        try:
            self.model = joblib.load('model.pkl')
            self.log_message("Model loaded successfully.", "INFO")
        except Exception as e:
            self.log_message(f"Could not load model: {e}", "ERR")
            self.model = None

    def log_message(self, message, level="NORMAL"):
        self.log_queue.put((message, level))

    def process_queue(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                self.log_area.config(state='normal')
                timestamp = time.strftime("%H:%M:%S")
                self.log_area.insert(tk.END, f"[{timestamp}] {msg}\n", level)
                self.log_area.see(tk.END)
                self.log_area.config(state='disabled')
                
                # Update stats if needed
                self.lbl_packets.config(text=f"Total Packets: {self.packet_count}")
                self.lbl_anomalies.config(text=f"Anomalies Detected: {self.anomaly_count}")
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)

    def start_server(self):
        self.running = True
        self.server_thread = threading.Thread(target=self.run_server, daemon=True)
        self.server_thread.start()

    def run_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((HOST, PORT))
            server.listen(1)
            self.status_var.set(f"Status: Listening on {HOST}:{PORT}")
            self.log_message(f"AI Engine listening on {HOST}:{PORT}...", "INFO")
            
            while self.running:
                conn, addr = server.accept()
                self.status_var.set(f"Status: Connected to {addr}")
                self.log_message(f"Sniffer connected: {addr}", "INFO")
                
                self.handle_client(conn)
                
                self.status_var.set(f"Status: Listening on {HOST}:{PORT}")
                self.log_message("Sniffer disconnected. Waiting...", "WARN")
                
        except Exception as e:
            self.log_message(f"Server Error: {e}", "ERR")
        finally:
            server.close()

    def handle_client(self, conn):
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
                        self.process_line(line)
            except Exception as e:
                self.log_message(f"Connection Error: {e}", "ERR")
                break
        conn.close()

    def process_line(self, line):
        try:
            # CSV: TS, MAC, IP, TRUSTED
            parts = line.split(',')
            if len(parts) >= 4:
                ts = int(parts[0])
                mac = parts[1]
                is_trusted = int(parts[3])
                
                self.packet_count += 1
                
                features = self.feature_extractor.process(mac, ts)
                
                if self.model:
                    prediction = self.model.predict(features)[0]
                    score = self.model.decision_function(features)[0]
                    
                    # Anomaly Detection Logic
                    confidence = -0.15
                    if prediction == -1 and score < confidence:
                        self.anomaly_count += 1
                        
                        local_freq = features[0][1]
                        global_freq = features[0][2]
                        delta = features[0][0]
                        
                        if is_trusted == 1:
                            msg = f"ALERT: Trusted Device {mac} behaving anomalously! Score: {score:.3f}"
                            self.log_message(msg, "ERR")
                        else:
                            msg = f"ALERT: Untrusted Device {mac} Attack detected! Score: {score:.3f}"
                            self.log_message(msg, "ERR")
                    elif is_trusted == 0:
                        self.log_message(f"ALERT: Unknown Device {mac} detected.", "WARN")
                        
        except ValueError:
            pass

if __name__ == "__main__":
    app = AIEngineGUI()
    app.mainloop()
