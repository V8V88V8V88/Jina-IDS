import numpy as np
import pandas as pd
from scapy.all import *

class FeatureExtractor:
    def __init__(self):
        self.columns = ["packet_length", "ttl", "src_port", "dst_port"]
gitch
    def extract(self, packet):
        try:
            length = len(packet)
            ttl = packet[IP].ttl if IP in packet else 0
            src_port = packet[TCP].sport if TCP in packet else 0
            dst_port = packet[TCP].dport if TCP in packet else 0
            return np.array([length, ttl, src_port, dst_port])
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return np.zeros(len(self.columns))