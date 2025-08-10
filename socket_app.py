import socket

# Create a raw socket and bind it to the public interface
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

print("[*] Starting raw socket packet sniffer... Press CTRL+C to stop.")

while True:
    raw_data, addr = conn.recvfrom(65535)
    print(f"Packet received from {addr}")
    print(raw_data)  # Raw bytes of the packet

