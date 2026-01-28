import numpy as np
from collections import deque, defaultdict

class FeatureExtractor:
    def __init__(self):
        # Stores global timestamps in a deque for efficient popping
        self.global_window = deque()
        # Maps MAC -> { 'last_ts': int, 'count_window': deque() }
        self.device_states = defaultdict(lambda: {'last_ts': 0, 'count_window': deque()})

    def process(self, mac, timestamp):
        """
        Calculates features for a single packet.
        Returns: np.array([[delta, local_freq, global_freq]])
        """
        # Global Frequency
        # Remove old timestamps (< timestamp - 60)
        while self.global_window and self.global_window[0] <= timestamp - 60:
            self.global_window.popleft()
        
        self.global_window.append(timestamp)
        global_freq = len(self.global_window)

        # Local Features
        state = self.device_states[mac]
        
        # Delta Time
        if state['last_ts'] == 0:
            delta = 1.0
        else:
            delta = float(timestamp - state['last_ts'])
            if delta == 0: delta = 0.01
        
        state['last_ts'] = timestamp

        # Local Frequency
        window = state['count_window']
        while window and window[0] <= timestamp - 60:
            window.popleft()
        
        window.append(timestamp)
        local_freq = len(window)

        return np.array([[delta, local_freq, global_freq]])

    def process_row(self, row, training_mode=True):
        """
        Helper for processing a pandas row or dict-like object during training/bulk processing.
        """
        ts = int(row['timestamp'])
        mac = row['mac']
        return self.process(mac, ts)
