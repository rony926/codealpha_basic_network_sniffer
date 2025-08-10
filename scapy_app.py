from scapy.all import sniff

# Packet handler function
def packet_handler(packet):
    print(packet.summary())  # Print basic packet info
    # Uncomment below to see full packet details
    # packet.show()

# Sniff packets on all interfaces
print("[*] Starting packet sniffer... Press CTRL+C to stop.")
#sniff(prn=packet_handler, store=False)
sniff(filter="tcp port 80", prn=packet_handler, store=False)

