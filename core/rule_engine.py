import json
import os
from netaddr import IPNetwork

class RuleEngine:
    def __init__(self, rules_file="data/rules/default_rules.json"):
        self.rules_file = rules_file
        self.rules = self.load_rules()

    def load_rules(self):
        if os.path.exists(self.rules_file):
            with open(self.rules_file, "r") as file:
                return json.load(file)
        return {}

    def check_packet(self, packet):
        src_ip = packet["IP"].src if "IP" in packet else None
        for rule in self.rules.get("blacklist", []):
            if src_ip and src_ip in IPNetwork(rule):
                print(f"Alert: Packet from blacklisted IP {src_ip}")
                return True
        return False

