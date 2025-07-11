# simple_test.py
from scapy.all import sniff, IP, get_if_list

def packet_test(packet):
    """A simple callback to print a message for each packet."""
    print("Packet captured!")
    if IP in packet:
        print(f"  Source: {packet[IP].src} -> Destination: {packet[IP].dst}")

if __name__ == '__main__':
    print("Available network interfaces:", get_if_list())
    print("\nStarting simple sniffer test... (Press Ctrl+C to stop)")
    print("Please open a web browser or generate some network traffic now.")
    
    # MODIFIED: Replace "Wi-Fi" or "Ethernet" with the correct name from the list above
    sniff(iface="Wi-Fi", prn=packet_test, count=10)
    
    print("Sniffer test finished.")