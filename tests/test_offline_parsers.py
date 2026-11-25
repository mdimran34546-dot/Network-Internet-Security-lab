#!/usr/bin/env python3
"""
Offline parser tests for src/sniffer.py (CYSE 228 Lab 01).

These tests build synthetic frames in memory with `struct` and check the
parsing functions directly. They NEVER open a socket and need no root
privileges, so they can run on any OS.

Run from the repository root:
    python3 tests/test_offline_parsers.py
    # or: python3 -m unittest discover -s tests
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import sniffer  # noqa: E402


def build_ipv4(ttl=64, proto=1, src=(10, 0, 2, 15), dst=(8, 8, 8, 8),
               ihl_nibble=0x5, total_len=None):
    """Build a minimal IPv4 header (20 bytes) with the given fields."""
    if total_len is None:
        total_len = 20
    return struct.pack(
        "!BBHHHBBH4s4s",
        (0x4 << 4) | ihl_nibble,   # version 4 + IHL nibble
        0,                          # TOS
        total_len,                  # total length
        0x1234,                     # identification
        0x4000,                     # flags (DF) / fragment offset
        ttl,                        # TTL
        proto,                      # protocol
        0,                          # header checksum (not validated here)
        bytes(src),
        bytes(dst),
    )


def build_tcp(sp=443, dp=51234, seq=1000, ack=2000, flags=0x18,
              data_offset=5):
    """Build a minimal TCP header (20 bytes) + small payload."""
    header = struct.pack(
        "!HHLLHHHH",
        sp, dp, seq, ack,
        (data_offset << 12) | flags,   # data offset + reserved + flags
        65535,                          # window
        0,                              # checksum
        0,                              # urgent pointer
    )
    return header + b"payload!"


class TestMacAddress(unittest.TestCase):
    def test_get_mac_addr_formatting(self):
        raw = bytes.fromhex("9a07d9e7c8fd")
        self.assertEqual(sniffer.get_mac_addr(raw), "9A:07:D9:E7:C8:FD")

    def test_broadcast_mac(self):
        self.assertEqual(sniffer.get_mac_addr(b"\xff" * 6),
                         "FF:FF:FF:FF:FF:FF")


class TestEthernet(unittest.TestCase):
    def test_valid_frame(self):
        frame = (b"\x00" * 6) + (b"\x11" * 6) + struct.pack("!H", 0x0800) + b"payload"
        dst, src, proto, payload = sniffer.ethernet_frame(frame)
        self.assertEqual(dst, "00:00:00:00:00:00")
        self.assertEqual(src, "11:11:11:11:11:11")
        self.assertEqual(proto, 0x0800)
        self.assertEqual(payload, b"payload")

    def test_truncated_frame_raises(self):
        with self.assertRaises(ValueError):
            sniffer.ethernet_frame(b"\x00" * 5)      # 5 bytes < 14
        with self.assertRaises(ValueError):
            sniffer.ethernet_frame(b"")               # empty frame


class TestIPv4(unittest.TestCase):
    def test_valid_packet(self):
        ip = build_ipv4()
        ver, hl, ttl, proto, src, dst, payload = sniffer.ipv4_packet(ip)
        self.assertEqual((ver, hl, ttl, proto), (4, 20, 64, 1))
        self.assertEqual(src, "10.0.2.15")
        self.assertEqual(dst, "8.8.8.8")
        self.assertEqual(payload, b"")

    def test_report_sample_values(self):
        """Values documented in the lab report: Ver 4, HL 20, TTL 64, Proto 1,
        10.0.2.15 -> 8.8.8.8."""
        ip = build_ipv4(ttl=64, proto=1)
        ver, hl, ttl, proto, src, dst, _ = sniffer.ipv4_packet(ip)
        self.assertEqual((ver, hl, ttl, proto, src, dst),
                         (4, 20, 64, 1, "10.0.2.15", "8.8.8.8"))

    def test_truncated_packet_raises(self):
        with self.assertRaises(ValueError):
            sniffer.ipv4_packet(build_ipv4()[:15])   # < 20 bytes

    def test_bogus_ihl_raises(self):
        with self.assertRaises(ValueError):
            sniffer.ipv4_packet(build_ipv4(ihl_nibble=0x1))  # IHL=4 bytes


class TestICMP(unittest.TestCase):
    def test_report_sample_echo_request(self):
        """Report sample: Type 8, Code 0, Checksum 41737."""
        icmp = struct.pack("!BBH", 8, 0, 41737) + b"data"
        icmp_type, code, checksum, rest = sniffer.icmp_packet(icmp)
        self.assertEqual((icmp_type, code, checksum), (8, 0, 41737))
        self.assertEqual(rest, b"data")

    def test_truncated_packet_raises(self):
        with self.assertRaises(ValueError):
            sniffer.icmp_packet(b"\x08\x00")          # 2 bytes < 4


class TestTCP(unittest.TestCase):
    def test_valid_segment(self):
        seg = build_tcp()
        sp, dp, seq, ack, flags, payload = sniffer.tcp_segment(seg)
        self.assertEqual((sp, dp, seq, ack), (443, 51234, 1000, 2000))
        self.assertEqual(flags["ACK"], 1)
        self.assertEqual(flags["PSH"], 1)
        self.assertEqual(sum(flags.values()), 2)      # only ACK+PSH set
        self.assertEqual(payload, b"payload!")

    def test_syn_flag(self):
        seg = build_tcp(flags=0x02)                   # SYN only
        _, _, _, _, flags, _ = sniffer.tcp_segment(seg)
        self.assertEqual(flags["SYN"], 1)
        self.assertEqual(sum(flags.values()), 1)

    def test_all_flags(self):
        seg = build_tcp(flags=0x3F)                   # URG|ACK|PSH|RST|SYN|FIN
        _, _, _, _, flags, _ = sniffer.tcp_segment(seg)
        self.assertTrue(all(flags.values()))

    def test_truncated_segment_raises(self):
        with self.assertRaises(ValueError):
            sniffer.tcp_segment(build_tcp()[:10])     # < 14 bytes

    def test_bogus_offset_is_clamped(self):
        # Malformed Data Offset of 0 in a full 20-byte TCP header:
        # the clamp must prevent the first 14 header bytes leaking as payload.
        header = struct.pack("!HHLLH", 443, 51234, 0, 0, (0x0 << 12) | 0x18)
        header += struct.pack("!HHH", 65535, 0, 0)       # window/checksum/urgent
        seg = header + b"payload"
        self.assertEqual(len(header), 20)
        _, _, _, _, _, payload = sniffer.tcp_segment(seg)
        self.assertEqual(payload, b"payload")


class TestFullFrameIntegration(unittest.TestCase):
    def test_ethernet_plus_ipv4_plus_icmp(self):
        """A complete Ethernet + IPv4 + ICMP echo request decodes to the
        values documented in the lab report."""
        eth = (bytes.fromhex("ffffffffffff") +
               bytes.fromhex("00e2693d13d2") +
               struct.pack("!H", 0x0800))
        ip = build_ipv4(ttl=64, proto=1,
                        src=(10, 0, 2, 15), dst=(8, 8, 8, 8))
        icmp = struct.pack("!BBH", 8, 0, 41737) + b"abcd"

        dst_mac, src_mac, eth_proto, eth_payload = sniffer.ethernet_frame(eth + ip + icmp)
        self.assertEqual(dst_mac, "FF:FF:FF:FF:FF:FF")
        self.assertEqual(src_mac, "00:E2:69:3D:13:D2")
        self.assertEqual(eth_proto, 0x0800)

        ver, hl, ttl, proto, src_ip, dst_ip, ip_payload = sniffer.ipv4_packet(eth_payload)
        self.assertEqual((ver, proto), (4, 1))
        self.assertEqual((src_ip, dst_ip), ("10.0.2.15", "8.8.8.8"))

        icmp_type, code, checksum, _ = sniffer.icmp_packet(ip_payload)
        self.assertEqual((icmp_type, code, checksum), (8, 0, 41737))


if __name__ == "__main__":
    unittest.main(verbosity=2)
