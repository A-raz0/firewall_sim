import argparse
import csv
import ipaddress
import logging
import random
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

@dataclass(frozen=True)
class Packet:
    src_ip: ipaddress.IPv4Address
    dst_port: int
    protocol: str
    payload_size: int


@dataclass
class Rule:
    name: str
    src: ipaddress.IPv4Network
    protocol: Optional[str] = None
    dst_port: Optional[int] = None
    action: str = "deny"

    hits: int = 0

    def matches(self, packet: Packet) -> bool:
        if packet.src_ip not in self.src:
            return False
        if self.protocol is not None and packet.protocol != self.protocol:
            return False
        if self.dst_port is not None and packet.dst_port != self.dst_port:
            return False
        return True

@dataclass
class Firewall:
    rules: List[Rule]
    default_action: str = "allow"
    counters: Dict[str, int] = field(default_factory=lambda: {"allow": 0, "deny": 0})
    top_sources: Dict[str, int] = field(default_factory=dict)

    def decide(self, packet: Packet) -> Tuple[str, Optional[str]]:
        """Return (action, matched_rule_name)."""
        src_str = str(packet.src_ip)
        self.top_sources[src_str] = self.top_sources.get(src_str, 0) + 1

        for rule in self.rules:
            if rule.matches(packet):
                rule.hits += 1
                self.counters[rule.action] += 1
                return rule.action, rule.name

        self.counters[self.default_action] += 1
        return self.default_action, None

    def summary(self, top_n: int = 5) -> str:
        total = sum(self.counters.values())
        allow = self.counters.get("allow", 0)
        deny = self.counters.get("deny", 0)

        lines = []
        lines.append("=== Summary ===")
        lines.append(f"Total packets: {total}")
        lines.append(f"Allowed: {allow}")
        lines.append(f"Denied:  {deny}")
        lines.append("")
        lines.append("Rule hit counts:")
        for r in self.rules:
            lines.append(f"  - {r.name}: {r.hits}")
        lines.append("")
        lines.append(f"Top {top_n} source IPs:")
        for ip, c in sorted(self.top_sources.items(), key=lambda x: x[1], reverse=True)[:top_n]:
            lines.append(f"  - {ip}: {c}")
        return "\n".join(lines)

def parse_network(value: str) -> ipaddress.IPv4Network:
    """
    Accepts:
      - "192.168.1.10" (treated as /32)
      - "192.168.1.0/24"
    """
    if "/" not in value:
        value = f"{value}/32"
    net = ipaddress.ip_network(value, strict=False)
    if not isinstance(net, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 is supported in this toy simulator.")
    return net


def load_default_rules() -> List[Rule]:
    blocked_ips = ["192.168.1.1", "192.168.1.4", "192.168.1.9",
                   "192.168.1.13", "192.168.1.16", "192.168.1.19"]

    rules: List[Rule] = []
    for ip in blocked_ips:
        rules.append(
            Rule(
                name=f"deny_{ip}",
                src=parse_network(ip),
                protocol=None,
                dst_port=None,
                action="deny",
            )
        )

    rules.append(Rule(name="deny_telnet_any", src=parse_network("192.168.1.0/24"), protocol="tcp", dst_port=23, action="deny"))
    rules.append(Rule(name="allow_dns_udp", src=parse_network("192.168.1.0/24"), protocol="udp", dst_port=53, action="allow"))
    return rules

def random_private_ip(subnet: str = "192.168.1.0/24") -> ipaddress.IPv4Address:
    net = ipaddress.ip_network(subnet, strict=False)
    hosts = list(net.hosts())
    return random.choice(hosts)


def generate_packets(n: int, subnet: str) -> Iterable[Packet]:
    ports_common = [22, 23, 53, 80, 443, 8080, 5000, 3306]
    protocols = ["tcp", "udp"]
    for _ in range(n):
        yield Packet(
            src_ip=random_private_ip(subnet),
            dst_port=random.choice(ports_common + [random.randint(1, 65535)]),
            protocol=random.choice(protocols),
            payload_size=random.randint(40, 1500),
        )

def read_packets_csv(path: str) -> List[Packet]:
    """
    CSV columns:
      src_ip,dst_port,protocol,payload_size
    """
    packets: List[Packet] = []
    with open(path, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append(
                Packet(
                    src_ip=ipaddress.ip_address(row["src_ip"]),
                    dst_port=int(row["dst_port"]),
                    protocol=row["protocol"].lower(),
                    payload_size=int(row["payload_size"]),
                )
            )
    return packets

def write_packets_csv(path: str, packets: Iterable[Packet]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src_ip", "dst_port", "protocol", "payload_size"])
        for p in packets:
            writer.writerow([str(p.src_ip), p.dst_port, p.protocol, p.payload_size])

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s")

def run_simulation(
    fw: Firewall,
    packets: Iterable[Packet],
    show_each: bool = True
) -> None:
    log = logging.getLogger("firewall")

    for i, p in enumerate(packets, start=1):
        action, rule = fw.decide(p)
        if show_each:
            rule_str = rule if rule else "default"
            log.info(
                f"[{i:04d}] src={p.src_ip} proto={p.protocol.upper():3s} "
                f"dport={p.dst_port:5d} size={p.payload_size:4d} => {action.upper():5s} ({rule_str})"
            )


def interactive_mode(fw: Firewall) -> None:
    print("Interactive mode. Enter packets like: <src_ip> <tcp|udp> <dst_port> <payload_size>")
    print("Example: 192.168.1.10 tcp 80 300")
    print("Type 'quit' to exit.\n")

    while True:
        line = input("> ").strip()
        if line.lower() in {"quit", "exit"}:
            break
        try:
            src_s, proto, dport_s, size_s = line.split()
            pkt = Packet(
                src_ip=ipaddress.ip_address(src_s),
                protocol=proto.lower(),
                dst_port=int(dport_s),
                payload_size=int(size_s),
            )
            action, rule = fw.decide(pkt)
            print(f"{action.upper()}  (matched: {rule or 'default'})\n")
        except Exception as e:
            print(f"Bad input: {e}\n")


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Toy Firewall Simulator")
    p.add_argument("--num", type=int, default=12, help="number of random packets to generate")
    p.add_argument("--subnet", type=str, default="192.168.1.0/24", help="source subnet for random traffic")
    p.add_argument("--seed", type=int, default=None, help="random seed for reproducibility")
    p.add_argument("--default", dest="default_action", choices=["allow", "deny"], default="allow", help="default policy")
    p.add_argument("--csv-in", type=str, default=None, help="read packets from CSV instead of generating")
    p.add_argument("--csv-out", type=str, default=None, help="write generated packets to CSV")
    p.add_argument("--quiet", action="store_true", help="do not print each packet decision")
    p.add_argument("--verbose", action="store_true", help="debug logging")
    p.add_argument("--interactive", action="store_true", help="interactive packet entry")
    return p


def main() -> None:
    args = build_argparser().parse_args()
    setup_logging(args.verbose)

    if args.seed is not None:
        random.seed(args.seed)

    fw = Firewall(rules=load_default_rules(), default_action=args.default_action)

    if args.interactive:
        interactive_mode(fw)
        print("\n" + fw.summary())
        return

    if args.csv_in:
        packets = read_packets_csv(args.csv_in)
    else:
        packets = list(generate_packets(args.num, args.subnet))
        if args.csv_out:
            write_packets_csv(args.csv_out, packets)

    run_simulation(fw, packets, show_each=not args.quiet)
    print("\n" + fw.summary())


if __name__ == "__main__":
    main()
