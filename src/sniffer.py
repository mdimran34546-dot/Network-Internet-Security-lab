#!/usr/bin/env python3
# =============================================================================
#  Python Socket Library for Network Packet Sniffing  -  RECONSTRUCTION
# =============================================================================
#  Course        : CYSE 228 - Network & Internet Security Sessional
#  Lab Report    : 01
#  Student       : Aminul Hoque Imran  (ID: 2304027)
#  Department    : Cyber Security Engineering
#  University    : University of Frontier Technology, Bangladesh (UFTB)
#
#  >>> IMPORTANT - READ THIS <<<
#  This file is a FAITHFUL RECONSTRUCTION assembled strictly from the code
#  fragments, function names, struct formats and sample outputs that appear in
#  the submitted lab report (assignment/original_lab_report.pdf). The original
#  `sniffer.py` was NOT recoverable from the PDF in full, so this version is
#  provided for reference/review and is NOT claimed to be the student's exact
#  original file. Any differences from the original program are accidental.
#
#  Verified fragments used to rebuild this file:
#    * import socket / import struct
#    * conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
#    * while True: raw_data, addr = conn.recvfrom(65536)
#    * ethernet_frame() -> struct.unpack('! 6s 6s H', data[:14])
#    * get_mac_addr()   -> map("{:02x}".format, ...) + .upper()
#    * IPv4 fields: Version, Header Length, TTL, Protocol, Source/Dest IP
#    * ICMP fields: Type, Code, Checksum
#    * TCP fields : Src/Dst Port, Seq, Ack, URG/ACK/PSH/RST/SYN/FIN, offset
#
#  RUNNING (requires Linux + root, e.g. Kali Linux):
#      sudo python3 sniffer.py
#  Generate traffic in another terminal to see packets:
#      ping 8.8.8.8
#
#  NOTE (added during audit): minimum-length guards and safe payload slicing
#  were added so that malformed / truncated frames are skipped with a warning
#  instead of crashing the capture loop. All logic from the report fragments
#  is unchanged.
# =============================================================================

import socket
import struct

# EtherType values we care about (host byte order after ntohs on the socket).
ETHERTYPE_IPV4 = 0x0800   # IPv4  (report text mentions "8" - see note below)
ETHERTYPE_IPV6 = 0x86DD   # IPv6
ETHERTYPE_ARP  = 0x0806   # ARP

# IP protocol numbers.
IPPROTO_ICMP = 1
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17


def get_mac_addr(bytes_addr):
    """Convert a 6-byte raw MAC address into AA:BB:CC:DD:EE:FF format."""
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()


def get_ipv4_addr(bytes_addr):
    """Convert a 4-byte raw IPv4 address into dotted-decimal format."""
    return '.'.join(map(str, bytes_addr))


def ethernet_frame(data):
    """
    Parse the Ethernet (Layer 2) header - the first 14 bytes:
        Destination MAC (6) | Source MAC (6) | EtherType/Protocol (2)
    Returns (dest_mac, src_mac, eth_proto, payload).
    """
    if len(data) < 14:
        raise ValueError(f"truncated Ethernet frame: {len(data)} bytes (need >= 14)")
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), eth_proto, data[14:]


def ipv4_packet(data):
    """
    Parse the IPv4 (Layer 3) header (minimum 20 bytes).
    Returns (version, header_length, ttl, proto, src_ip, dst_ip, payload).
    """
    if len(data) < 20:
        raise ValueError(f"truncated IPv4 packet: {len(data)} bytes (need >= 20)")
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4
    if header_length < 20:
        raise ValueError(f"invalid IPv4 header length: {header_length} bytes")
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return (version, header_length, ttl, proto,
            get_ipv4_addr(src), get_ipv4_addr(target), data[header_length:])


def icmp_packet(data):
    """Parse an ICMP packet (Type, Code, Checksum)."""
    if len(data) < 4:
        raise ValueError(f"truncated ICMP packet: {len(data)} bytes (need >= 4)")
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    """
    Parse a TCP segment header (first 14 bytes used here):
        Src Port (2) | Dst Port (2) | Seq (4) | Ack (4) | Offset+Flags (2)
    Returns (src_port, dst_port, seq, ack, flags_dict, payload).
    """
    if len(data) < 14:
        raise ValueError(f"truncated TCP segment: {len(data)} bytes (need >= 14)")
    src_port, dst_port, sequence, acknowledgment, offset_reserved_flags = \
        struct.unpack('! H H L L H', data[:14])

    # Data Offset lives in the top 4 bits; *4 converts 32-bit words to bytes.
    offset = (offset_reserved_flags >> 12) * 4
    if offset < 20:
        # Guard against a malformed Data Offset (minimum TCP header is 20 bytes).
        offset = 20

    # The low 6 bits are the control flags URG, ACK, PSH, RST, SYN, FIN.
    flags = offset_reserved_flags & 0x3F
    flag_dict = {
        'URG': (flags >> 5) & 1,
        'ACK': (flags >> 4) & 1,
        'PSH': (flags >> 3) & 1,
        'RST': (flags >> 2) & 1,
        'SYN': (flags >> 1) & 1,
        'FIN':  flags       & 1,
    }
    return src_port, dst_port, sequence, acknowledgment, flag_dict, data[offset:]


def print_ethernet(dest_mac, src_mac, eth_proto):
    print('\n' + '=' * 60)
    print('Ethernet Frame:')
    print(f'  Destination MAC : {dest_mac}')
    print(f'  Source MAC      : {src_mac}')
    print(f'  Protocol        : {eth_proto} (0x{eth_proto:04X})')


def main():
    # Create a raw socket that captures at the Ethernet layer.
    #   AF_PACKET -> capture at Layer 2
    #   SOCK_RAW  -> raw packet data (no kernel processing)
    #   ntohs(3)  -> ETH_P_ALL: capture every protocol (all EtherTypes)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print('Network Packet Sniffer Started')
    print('Listening on all interfaces (Ctrl+C to stop)...\n')

    while True:
        raw_data, addr = conn.recvfrom(65536)
        try:
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print_ethernet(dest_mac, src_mac, eth_proto)

            if eth_proto == ETHERTYPE_IPV4:
                version, hl, ttl, proto, src_ip, dst_ip, ip_data = ipv4_packet(data)
                print('IPv4 Packet:')
                print(f'  Version        : {version}')
                print(f'  Header Length  : {hl}')
                print(f'  TTL            : {ttl}')
                print(f'  Protocol       : {proto}')
                print(f'  Source IP      : {src_ip}')
                print(f'  Destination IP : {dst_ip}')

                if proto == IPPROTO_ICMP:
                    icmp_type, code, checksum, _ = icmp_packet(ip_data)
                    print('ICMP Packet:')
                    print(f'  Type     : {icmp_type}')
                    print(f'  Code     : {code}')
                    print(f'  Checksum : {checksum}')

                elif proto == IPPROTO_TCP:
                    (s_port, d_port, seq, ack,
                     flags, payload) = tcp_segment(ip_data)
                    print('TCP Segment:')
                    print(f'  Source Port      : {s_port}')
                    print(f'  Destination Port : {d_port}')
                    print(f'  Sequence Number  : {seq}')
                    print(f'  Ack Number       : {ack}')
                    print('  Flags            : ' +
                          ' '.join(name for name, val in flags.items() if val))
                    print(f'  Payload length   : {len(payload)} bytes')

                elif proto == IPPROTO_UDP:
                    print('UDP Segment: (analysis not covered in lab report)')

            elif eth_proto == ETHERTYPE_ARP:
                print('ARP Packet')
            elif eth_proto == ETHERTYPE_IPV6:
                print('IPv6 Packet (analysis not covered in lab report)')
            else:
                print('Other / Non-IP Ethernet payload')

        except (ValueError, struct.error, IndexError) as exc:
            # Malformed or truncated frame: warn and keep capturing.
            print(f'[!] Skipped malformed frame ({len(raw_data)} bytes): {exc}')


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        print('\n[!] Permission denied: run this script as root (sudo).')
    except KeyboardInterrupt:
        print('\n[*] Sniffer stopped by user.')
