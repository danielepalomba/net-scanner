import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from collections import defaultdict


def extract_features(df):
    """
    Translates the collected raw data into meaningful numbers for the model. The following steps are performed, in order:

    1. Data preparation -> all packets are sorted chronologically.

    2. Memory -> a dictionary is created that tracks the state of each device, for each MAC, remembers last_ts
    (when it sent the last packet), count_window (list of all packets sent in the last 60 seconds). Is also mantained a global frequency. 

    3. Global Frequency -> calculates how many packets globally. 
    
    4. Delta-Time -> measures how quickly the device sends packets.

    5. Local Frequency -> calculates how many packets it sent in the last minute.

    6. Output -> matrix where each row represents a packet.
    """

    df = df.sort_values(by='timestamp')

    feature_list = []

    history = defaultdict(lambda: {'last_ts': 0, 'count_window': []})

    global_window = []

    for _, row in df.iterrows():
        ts = int(row['timestamp'])
        mac = row['mac']

        global_window = [t for t in global_window if t > ts - 60]
        global_window.append(ts)
        global_freq = len(global_window)

        state = history[mac]

        if state['last_ts'] == 0:
            delta = 1.0
        else:
            delta = ts - state['last_ts']
            if delta == 0: delta = 0.01

        state['last_ts'] = ts

        state['count_window'] = [t for t in state['count_window'] if t > ts - 60]
        state['count_window'].append(ts)
        local_freq = len(state['count_window'])

        feature_list.append([delta, local_freq, global_freq])

    return np.array(feature_list)


print("Loading dataset...")
df = pd.read_csv('dataset.csv')

print(f"Extracting features from {len(df)} packets...")
X = extract_features(df)

"""
Given the lack of labeled data from attacks of this kind, 
I use Isolation Forest (Unsupervised), as it can train on "normal" traffic. 
Furthermore, Isolation Forest has a computational time of O(n), making it very fast. 
This is exactly what I was looking for, since the sniffer is written in C, making it very efficient.
"""
print("Training...")
model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
model.fit(X)

joblib.dump(model, 'model.pkl')
print("Completed!")
