import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from collections import defaultdict
from colorama import Fore, Back, Style

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
    
    # Use the shared FeatureExtractor class
    from features import FeatureExtractor
    extractor = FeatureExtractor()

    for _, row in df.iterrows():
        # process returns [[features]], we need just [features]
        feats = extractor.process_row(row)[0] 
        feature_list.append(feats)

    return np.array(feature_list)


print(Style.BRIGHT + Fore.BLACK + Back.GREEN + "Loading dataset...")
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
