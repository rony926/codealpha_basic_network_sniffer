import socket
import struct

# Ethernet header parsing
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('!6s6sH', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(format(b, '02x') for b in bytes_addr)

# IPv4 header parsing
def ipv4_packet(data):
    version_header_length = data[0]
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('!8xBB2x4s4s', data[:20])
    return ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

# TCP segment parsing
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('!HHLLH', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, sequence, acknowledgment, data[offset:]

# UDP segment parsing
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('!HHH2x', data[:8])
    return src_port, dest_port, size, data[8:]

# ICMP packet parsing
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

# Main Sniffer
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print("[*] Packet sniffer started... Press CTRL+C to stop.\n")

    while True:
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(f"  Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        # IPv4
        if eth_proto == 8:
            ttl, proto, src, target, data = ipv4_packet(data)
            print(f"  IPv4 Packet: {src} -> {target} | TTL: {ttl}")

            # TCP
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, payload = tcp_segment(data)
                print(f"  TCP Segment: {src_port} -> {dest_port} | Seq: {sequence}, Ack: {acknowledgment}")
                print(f"  Payload: {payload}")

            # UDP
            elif proto == 17:
                src_port, dest_port, size, payload = udp_segment(data)
                print(f"  UDP Segment: {src_port} -> {dest_port} | Length: {size}")
                print(f"  Payload: {payload}")

            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, payload = icmp_packet(data)
                print(f"  ICMP Packet: Type={icmp_type}, Code={code}, Checksum={checksum}")
                print(f"  Payload: {payload}")

            else:
                print(f"  Other IPv4 Protocol: {proto}")

if __name__ == "__main__":
    main()

