import time
from datetime import datetime
from dataclasses import dataclass
from typing import List, Optional

# --- Data Structures ---

@dataclass
class Packet:
    """Represents a network packet."""
    source_ip: str
    dest_port: int
    protocol: str
    payload: str

class Rule:
    """Represents a firewall rule."""
    def __init__(self, action: str, ip: str = "*", port: str = "*", protocol: str = "*"):
        self.action = action.upper()  # ALLOW or BLOCK
        self.ip = ip                  # Specific IP or '*' for any
        self.port = port              # Specific Port or '*' for any
        self.protocol = protocol.upper() # TCP, UDP, ICMP, or '*'

    def matches(self, packet: Packet) -> bool:
        """Checks if a packet matches this rule criteria."""
        if self.ip != "*" and self.ip != packet.source_ip:
            return False
        
        # Handle port matching (convert to string for comparison, handle wildcard)
        if self.port != "*" and str(self.port) != str(packet.dest_port):
            return False
            
        if self.protocol != "*" and self.protocol != packet.protocol.upper():
            return False
            
        return True

    def __str__(self):
        return f"[{self.action}] IP: {self.ip} | Port: {self.port} | Proto: {self.protocol}"

# --- Firewall Engine ---

class Firewall:
    def __init__(self):
        self.rules: List[Rule] = []
        self.logs: List[str] = []
        # Default policy if no rules match (Standard is usually BLOCK, but we'll use ALLOW for demo)
        self.default_policy = "ALLOW" 

    def add_rule(self, action, ip, port, protocol):
        new_rule = Rule(action, ip, port, protocol)
        self.rules.append(new_rule)
        print(f"✅ Rule Added: {new_rule}")

    def log_action(self, packet, action, reason):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = (f"[{timestamp}] Action: {action} | IP: {packet.source_ip} | "
                     f"Port: {packet.dest_port} | Proto: {packet.protocol} | Reason: {reason}")
        self.logs.append(log_entry)
        return log_entry

    def process_packet(self, packet: Packet):
        """
        Core Logic: Iterate through rules top-down. 
        First match determines the action.
        """
        print(f"\n📨 Processing Packet from {packet.source_ip}:{packet.dest_port} ({packet.protocol})...")
        
        for rule in self.rules:
            if rule.matches(packet):
                log = self.log_action(packet, rule.action, f"Matched Rule: {rule}")
                print(f"   ➜ {log}")
                return

        # If no rules match, use default policy
        log = self.log_action(packet, self.default_policy, "Default Policy (No Match)")
        print(f"   ➜ {log}")

    def show_logs(self):
        print("\n--- Firewall Logs ---")
        if not self.logs:
            print("No logs available.")
        for log in self.logs:
            print(log)
        print("---------------------")

    def show_rules(self):
        print("\n--- Active Rules ---")
        if not self.rules:
            print("No rules defined. Default Policy: ALLOW")
        for idx, rule in enumerate(self.rules):
            print(f"{idx+1}. {rule}")
        print("--------------------")

# --- CLI Interface ---

def get_input(prompt, default="*"):
    val = input(f"{prompt} (default '{default}'): ").strip()
    return val if val else default

def main():
    fw = Firewall()
    print("🛡️  Simple Firewall Simulator Started")
    
    while True:
        print("\nCOMMANDS: [1] Add Rule  [2] Send Packet  [3] Show Rules  [4] Show Logs  [5] Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            print("\n--- Configure New Rule ---")
            action = input("Action (ALLOW/BLOCK): ").strip().upper()
            if action not in ['ALLOW', 'BLOCK']:
                print("❌ Invalid Action. Must be ALLOW or BLOCK.")
                continue
            
            ip = get_input("Source IP")
            port = get_input("Dest Port")
            proto = get_input("Protocol (TCP/UDP/ICMP)")
            
            fw.add_rule(action, ip, port, proto)

        elif choice == '2':
            print("\n--- Generate Test Packet ---")
            ip = input("Source IP (e.g., 192.168.1.50): ").strip()
            if not ip: 
                print("❌ IP required"); continue
                
            try:
                port = int(input("Dest Port (e.g., 80, 443): ").strip())
            except ValueError:
                print("❌ Port must be a number"); continue
                
            proto = input("Protocol (TCP/UDP): ").strip().upper()
            payload = "Test Data"
            
            pkt = Packet(ip, port, proto, payload)
            fw.process_packet(pkt)

        elif choice == '3':
            fw.show_rules()

        elif choice == '4':
            fw.show_logs()

        elif choice == '5':
            print("Exiting Firewall...")
            break
        else:
            print("Invalid command.")

if __name__ == "__main__":
    main()

"""
FIREWALL LOGIC ARCHITECTURE:
---------------------------
1. Packet Arrival: The simulator receives a 'Packet' object containing 
   Source IP, Destination Port, and Protocol.

2. Sequential Evaluation: The engine iterates through the 'rules' list 
   from top to bottom (Index 0 -> N).

3. First-Match-Wins: 
   - For each rule, we check if (IP matches) AND (Port matches) AND (Protocol matches).
   - If ALL three match, the action (ALLOW or BLOCK) is taken immediately.
   - The engine STOPS searching further rules once a match is found.

4. Implicit Deny/Allow: 
   - If the packet reaches the end of the list without matching any rule, 
     it triggers the 'Default Policy'.
"""