from scapy.all import sniff, IP, TCP
import time

# Dictionary to track IPs sending SYN packets (used in port scanning detection)
syn_packet_count = {}

# Function to analyze packets
def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
        
        # Detecting SYN scan (common in port scans)
        if packet.haslayer(TCP) and packet[TCP].flags == 'S':  # SYN flag set
            if ip_src in syn_packet_count:
                syn_packet_count[ip_src] += 1
            else:
                syn_packet_count[ip_src] = 1
            
            if syn_packet_count[ip_src] > 10:  # Threshold for SYN flood or scan detection
                print(f"[ALERT] Possible Port Scan Detected from {ip_src} at {packet_time}")
                log_alert(f"Port scan from {ip_src} to {ip_dst} at {packet_time}")
        
        # Example of detecting unusually large packets
        if len(packet) > 1500:
            print(f"[ALERT] Large packet detected from {ip_src} to {ip_dst} at {packet_time}")
            log_alert(f"Large packet from {ip_src} to {ip_dst} at {packet_time}")

# Function to log alerts to a file
def log_alert(message):
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")

# Sniffing packets and applying analysis
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=analyze_packet, store=False, filter="ip")

if __name__ == "__main__":
    start_sniffing()
