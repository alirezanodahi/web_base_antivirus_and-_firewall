import socket as skt
import threading

# Define a class to represent a firewall rule


class FirewallRule:
    def __init__(self, src_ip, src_port, dst_ip, dst_port, dns_allowed):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dns_allowed = dns_allowed

# Define a class to handle incoming packets


class PacketHandler:
    def __init__(self, firewall_rules):
        self.firewall_rules = firewall_rules

    def handle_packet(self, packet_data):
        # Parse the packet data
        packet = packet_data.decode('utf-8')

        # Check if the packet is a DNS request
        if packet.startswith('dns'):
            # Check if DNS requests are allowed
            for rule in self.firewall_rules:
                if rule.dns_allowed:
                    break
            else:
                # Discard the packet if DNS requests are not allowed
                print("Discarding DNS request:", packet)
                return

        # Extract the source IP, destination IP, source port, and destination port
        src_ip, src_port, dst_ip, dst_port = packet.split(' ')[1:5]

        # Check if the packet matches any of the firewall rules
        for rule in self.firewall_rules:
            if (rule.src_ip == src_ip and rule.src_port == src_port) or \
                    (rule.dst_ip == dst_ip and rule.dst_port == dst_port):
                # Allow the packet if it matches a firewall rule
                print("Allowing packet:", packet)
                return
        else:
            # Discard the packet if it doesn't match any firewall rules
            print("Discarding packet:", packet)
            return

# Define a function to read firewall rules from a file


def read_firewall_rules(filename):
    rules = []

    with open(filename) as file:
        for line in file:
            # Parse the line into a firewall rule object
            rule_data = line.strip().split(' ')
            if len(rule_data) != 6:
                continue

            src_ip, src_port, dst_ip, dst_port, dns, allowed = rule_data
            rule = FirewallRule(src_ip, src_port, dst_ip,
                                dst_port, bool(int(allowed)))
            rules.append(rule)
    print(rules)
    return rules

# Define a function to start the firewall


def start_firewall(firewall_rules):
    packet_handler = PacketHandler(firewall_rules)

    # Create a socket to listen for incoming packets
    socket = skt.socket(skt.AF_INET, skt.SOCK_DGRAM)
    socket.bind(('', 53))  # Listen on port 53 for DNS requests

    while True:
        try:
            # Receive data from the socket
            packet_data, address = socket.recvfrom(1024)
        except skt.timeout:
            continue

        # Handle the incoming packet
        packet_handler.handle_packet(packet_data.decode('utf-8'))


# Main function
if __name__ == '__main__':
    # Read firewall rules from a file
    firewall_rules = read_firewall_rules('firewall_rules.txt')

    # Start the firewall
    start_firewall(firewall_rules)