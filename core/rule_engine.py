import json
import os
from netaddr import IPNetwork

class RuleEngine:
    def __init__(self, rules_file="data/rules/default_rules.json"):
        self.rules_file = rules_file
        self.rules = self.load_rules()  # Make sure this function exists!

    def load_rules(self):  # <- This method must be inside the class!
        if os.path.exists(self.rules_file):
            with open(self.rules_file, "r") as file:
                rules = json.load(file)
            if isinstance(rules, list):
                return rules
            else:
                print("Error: Rules file format is incorrect.")
                return []
        return []

    def check_packet(self, packet):
        src_ip = packet["IP"].src if "IP" in packet else None
        for rule in self.rules:
            if "ip_blacklist" in rule and isinstance(rule["ip_blacklist"], list):
                for blocked_ip in rule["ip_blacklist"]:
                    if src_ip and src_ip in IPNetwork(blocked_ip):
                        print(f"Alert: Packet from blacklisted IP {src_ip}")
                        return True
        return False
