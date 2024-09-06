from scapy.all import sniff, IP, TCP, UDP, ICMP
import time

# Initialize counters for analysis
packet_count = {"TCP": 0, "UDP": 0, "ICMP": 0}
packet_log = []

# Function to analyze packets
def analyze_packet(packet):
    global packet_count
    packet_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if packet.haslayer(TCP):
            packet_count["TCP"] += 1
            tcp_flags = packet[TCP].flags
            if tcp_flags == 'S':  # SYN flag
                print(f"[ALERT] SYN Packet from {ip_src} to {ip_dst} at {packet_time}")
                log_alert(f"SYN Packet from {ip_src} to {ip_dst} at {packet_time}")
                
        elif packet.haslayer(UDP):
            packet_count["UDP"] += 1
            udp_len = packet[UDP].len
            if udp_len > 1500:  # Unusually large UDP packet
                print(f"[ALERT] Large UDP Packet from {ip_src} to {ip_dst} at {packet_time}")
                log_alert(f"Large UDP Packet from {ip_src} to {ip_dst} at {packet_time}")
                
        elif packet.haslayer(ICMP):
            packet_count["ICMP"] += 1
            icmp_type = packet[ICMP].type
            if icmp_type == 8:  # Echo Request (Ping)
                print(f"[INFO] ICMP Echo Request from {ip_src} to {ip_dst} at {packet_time}")
                log_info(f"ICMP Echo Request from {ip_src} to {ip_dst} at {packet_time}")
    
    # Print packet counts every 10 seconds
    if int(time.time()) % 10 == 0:
        print(f"[STATS] TCP: {packet_count['TCP']} UDP: {packet_count['UDP']} ICMP: {packet_count['ICMP']}")
        
    packet_log.append(f"{packet_time} - {packet.summary()}")

# Function to log alerts to a file
def log_alert(message):
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")

# Function to log information to a file
def log_info(message):
    with open("info_log.txt", "a") as log_file:
        log_file.write(f"{message}\n")

# Sniffing packets and applying analysis
def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=analyze_packet, store=False, filter="ip")

if __name__ == "__main__":
    start_sniffing()
