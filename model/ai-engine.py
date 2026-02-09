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
        # Modern color scheme
        bg_dark = "#1e1e2e"
        bg_darker = "#11111b"
        accent_blue = "#89b4fa"
        accent_purple = "#cba6f7"
        text_light = "#cdd6f4"
        text_muted = "#a6adc8"
        success_bg = "#a6e3a1"
        warning_bg = "#fab387"
        error_bg = "#f38ba8"
        
        # Configure main window
        self.configure(bg=bg_dark)
        
        # Modern gradient-style header
        header_frame = tk.Frame(self, bg=accent_purple, height=70)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        header_label = tk.Label(
            header_frame, 
            text="Net-Scanner AI Monitor", 
            font=("Segoe UI", 20, "bold"), 
            bg=accent_purple, 
            fg="white"
        )
        header_label.pack(pady=20)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Stopped")
        status_label = tk.Label(
            self, 
            textvariable=self.status_var, 
            relief=tk.FLAT, 
            anchor="w",
            bg=bg_darker,
            fg=text_light,
            font=("Segoe UI", 10),
            padx=10,
            pady=5
        )
        status_label.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Main Area with dark background
        main_frame = tk.Frame(self, bg=bg_dark)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Stats Panel - Modern card style
        stats_frame = tk.Frame(main_frame, bg=bg_dark)
        stats_frame.pack(side=tk.TOP, fill=tk.X, pady=(0, 15))
        
        # Packet Count Card
        packet_card = tk.Frame(stats_frame, bg=bg_darker, relief=tk.FLAT, bd=0)
        packet_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        packet_title = tk.Label(
            packet_card, 
            text="TOTAL PACKETS", 
            font=("Segoe UI", 9), 
            bg=bg_darker, 
            fg=text_muted
        )
        packet_title.pack(pady=(10, 5), padx=15, anchor="w")
        
        self.lbl_packets = tk.Label(
            packet_card, 
            text="0", 
            font=("Segoe UI", 24, "bold"), 
            bg=bg_darker, 
            fg=accent_blue
        )
        self.lbl_packets.pack(pady=(0, 10), padx=15, anchor="w")
        
        # Anomaly Count Card
        anomaly_card = tk.Frame(stats_frame, bg=bg_darker, relief=tk.FLAT, bd=0)
        anomaly_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        anomaly_title = tk.Label(
            anomaly_card, 
            text="ANOMALIES DETECTED", 
            font=("Segoe UI", 9), 
            bg=bg_darker, 
            fg=text_muted
        )
        anomaly_title.pack(pady=(10, 5), padx=15, anchor="w")
        
        self.lbl_anomalies = tk.Label(
            anomaly_card, 
            text="0", 
            font=("Segoe UI", 24, "bold"), 
            bg=bg_darker, 
            fg=error_bg
        )
        self.lbl_anomalies.pack(pady=(0, 10), padx=15, anchor="w")
        
        self.packet_count = 0
        self.anomaly_count = 0
        
        # Logs - Modern style with larger font
        log_frame = tk.Frame(main_frame, bg=bg_darker, relief=tk.FLAT)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        log_title = tk.Label(
            log_frame,
            text="Event Log",
            font=("Segoe UI", 11, "bold"),
            bg=bg_darker,
            fg=text_light,
            anchor="w"
        )
        log_title.pack(fill=tk.X, padx=15, pady=(10, 5))
        
        # Scrolled text with larger, more readable font
        self.log_area = scrolledtext.ScrolledText(
            log_frame, 
            state='disabled', 
            font=("Consolas", 12),  # Increased from 10 to 12
            bg="#181825",
            fg=text_light,
            relief=tk.FLAT,
            padx=10,
            pady=10,
            spacing1=2,  # Add spacing before each line
            spacing3=2,  # Add spacing after each line
            wrap=tk.WORD
        )
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        # Enhanced tags for better readability with backgrounds
        self.log_area.tag_config("INFO", foreground=success_bg, font=("Consolas", 12, "bold"))
        self.log_area.tag_config("WARN", foreground=warning_bg, font=("Consolas", 12, "bold"))
        self.log_area.tag_config("ERR", foreground=error_bg, background="#3d1e21", font=("Consolas", 12, "bold"))
        self.log_area.tag_config("NORMAL", foreground=text_light)

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
                self.lbl_anomalies.config(text=f"Detected: {self.anomaly_count}")
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
