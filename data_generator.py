import pandas as pd
from scapy.all import rdpcap, IP
import random
from datetime import datetime, timedelta

def generate_network_data(filename="network_traffic.csv", num_packets=1000):
    """Generates synthetic network traffic data and saves it to a CSV file."""
    data = []
    start_time = datetime.now()

    for i in range(num_packets):
        # Simulate normal traffic
        src_ip = f"192.168.1.{random.randint(1, 100)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53])
        protocol = random.choice(["TCP", "UDP"])
        packet_size = random.randint(64, 1500)
        timestamp = start_time + timedelta(seconds=i)

        # Introduce some anomalies
        if i % 100 == 0:
            src_ip = "192.168.1.200" # An unusual source IP
            dst_port = 12345 # An unusual destination port
            packet_size = random.randint(2000, 3000) # Larger packet size

        data.append([timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_size])

    df = pd.DataFrame(data, columns=["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packet_size"])
    df.to_csv(filename, index=False)
    print(f"Generated {num_packets} packets and saved to {filename}")

if __name__ == "__main__":
    generate_network_data()