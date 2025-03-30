from core.analyzer import PacketAnalyzer
from core.packet_capture import PacketCapture

class ThreatDetector:
    def __init__(self):
        self.analyzer = PacketAnalyzer()
        self.capture = PacketCapture()

    def run(self):
        for packet in self.capture.start_capture():
            self.analyzer.analyze_packet(packet)

if __name__ == "__main__":
    detector = ThreatDetector()
    detector.run()
