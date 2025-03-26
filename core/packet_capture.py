import scapy.all as scapy
import pyshark

class PacketCapture:
    def __init__(self, interface="eth0", capture_file="data/logs/capture.pcap"):
        self.interface = interface
        self.capture_file = capture_file

    def start_capture(self):
        print(f"Starting packet capture on {self.interface}...")
        capture = pyshark.LiveCapture(interface=self.interface, output_file=self.capture_file)
        for packet in capture.sniff_continuously(packet_count=100):
            print(packet)

if __name__ == "__main__":
    capture = PacketCapture()
    capture.start_capture()
