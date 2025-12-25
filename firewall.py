import random

firewall_rules = [
    {"ip": "192.168.1.1", "protocol": "ANY", "port": "ANY", "action": "deny"},
    {"ip": "192.168.1.5", "protocol": "ANY", "port": "ANY", "action": "deny"},
    {"ip": "192.168.1.10", "protocol": "ANY", "port": "ANY", "action": "deny"},
    {"ip": "192.168.1.15", "protocol": "ANY", "port": "ANY", "action": "deny"},
    {"ip": "192.168.1.19", "protocol": "ANY", "port": "ANY", "action": "deny"},
    {"ip": "ANY", "protocol": "tcp", "port": 23, "action": "deny"},
    {"ip": "ANY", "protocol": "udp", "port": 53, "action": "allow"}
]
default_policy = "allow"

def generate_ip():
    return f"192.168.1.{random.randint(1, 20)}"

def generate_packet():
    packet = {
        "ip": generate_ip(),
        "protocol": random.choice(["tcp", "udp"]),
        "port": random.randint(1, 100),
        "size": random.randint(20, 1500)
    }
    return packet
    
def rule_matches(rule, packet):
    if rule["ip"] != "ANY" and rule["ip"] != packet["ip"]:
        return False
    if rule["protocol"] != "ANY" and rule["protocol"] != packet["protocol"]:
        return False
    if rule["port"] != "ANY" and rule["port"] != packet["port"]:
        return False
    return True

def check_firewall(packet, rules):
    for rule in rules:
        if rule_matches(rule, packet):
            return rule["action"], rule
    return default_policy, None

def simulate(num_packets):
    allowed = 0
    denied = 0
    rule_counts = {}
    for i in range(1, num_packets + 1):
        packet = generate_packet()
        action, matched_rule = check_firewall(packet, firewall_rules)
        if action == "allow":
            allowed += 1
        else:
            denied += 1
        if matched_rule is None:
            rule_name = "default_policy"
        else:
            rule_name = f'{matched_rule["action"].upper()} ip={matched_rule["ip"]} proto={matched_rule["protocol"]} port={matched_rule["port"]}'
            rule_counts[rule_name] = rule_counts.get(rule_name, 0) + 1
        print(
            f"[{i:04}] IP={packet['ip']} PROTO={packet['protocol'].upper()} PORT={packet['port']} SIZE={packet['size']:04} ACTION={action.upper()} RULE={rule_name}"
            f"=> {action.upper()} (matched rule: {rule_name})"
        )

    total = allowed + denied
    print("\nSimulation Summary:")
    print(f"Total packets processed: {total}")
    print(f"Allowed: {allowed}")
    print(f"Denied: {denied}")
    print("\nRule Match Counts:")
    for name, hits in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{name}: {hits} hits")

def main():
    num_packets = 100
    simulate(num_packets)

if __name__ == "__main__":
    main()