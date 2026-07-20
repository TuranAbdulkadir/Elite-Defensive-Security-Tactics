from scapy.all import rdpcap, TCP, UDP

class NetworkDefender:
    def __init__(self, pcap_file):
        self.packets = rdpcap(pcap_file)
        
    def detect_port_scan(self):
        syn_count = {}
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
                src = pkt.sprintf("%IP.src%")
                syn_count[src] = syn_count.get(src, 0) + 1
        for ip, count in syn_count.items():
            if count > 100:
                print(f"[ALERT] Potential Port Scan detected from {ip} ({count} SYN packets)")
