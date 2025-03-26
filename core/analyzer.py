from rule_engine import RuleEngine
from ml.predict import predict_packet

class PacketAnalyzer:
    def __init__(self):
        self.rule_engine = RuleEngine()

    def analyze_packet(self, packet):
        if self.rule_engine.check_packet(packet):
            print("Threat detected (rule-based)!")
        else:
            predict_packet(packet)  # ML-based detection