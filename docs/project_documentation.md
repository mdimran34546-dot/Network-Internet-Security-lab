# Project Documentation — Python Socket Library for Network Packet Sniffing

**Course:** CYSE 228 — Network & Internet Security Sessional
**Lab Report:** 01
**Student:** Aminul Hoque Imran (ID: 2304027)
**University:** University of Frontier Technology, Bangladesh (UFTB)

> **Source note:** This documentation describes `src/sniffer.py`, which is a
> *reconstruction* built from the code fragments in `assignment/original_lab_report.pdf`.
> The original PDF did not contain the complete program. The behaviour documented
> here follows the report's described functionality and the reconstructed code.

---

## 1. Overview

The program is a simple **promiscuous packet sniffer** written in Python. It opens
a raw socket at the **Ethernet (Link) layer** and prints a decoded view of every
frame that arrives on the interface. It focuses on four protocols:

| Layer | Protocol | What is extracted |
|---|---|---|
| 2 | Ethernet | Destination MAC, Source MAC, EtherType |
| 3 | IPv4 | Version, Header Length, TTL, Protocol, Src/Dst IP |
| 3 (control) | ICMP | Type, Code, Checksum |
| 4 | TCP | Src/Dst Port, Seq, Ack, Flags, Payload offset |

---

## 2. Execution Workflow

```
[ Start ]  sudo python3 sniffer.py
    |
    v
[ Create raw socket ]
    conn = socket.socket(AF_PACKET, SOCK_RAW, ntohs(3))
    |
    v
[ Capture loop ]  while True:
    raw_data, addr = conn.recvfrom(65536)
    |
    v
[ ethernet_frame(raw_data) ]  -> dest_mac, src_mac, eth_proto, payload
    |
    +-- eth_proto == 0x0800 (IPv4) ?
    |       |
    |       v
    |   [ ipv4_packet(payload) ] -> version, hl, ttl, proto, src, dst, ip_payload
    |       |
    |       +-- proto == 1 (ICMP) ? --> [ icmp_packet(ip_payload) ]
    |       +-- proto == 6 (TCP)  ? --> [ tcp_segment(ip_payload) ]
    |
    +-- else: print ARP / IPv6 / other
    |
    v
[ Print decoded fields ]  -> console
    |
    v
[ Repeat ]  (until Ctrl+C)
```

To see packets, generate traffic in another terminal, e.g. `ping 8.8.8.8`.

---

## 3. Important Functions

### `get_mac_addr(bytes_addr)`
Formats a 6-byte MAC address as `AA:BB:CC:DD:EE:FF`.

```python
return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
```
Each byte is formatted as two lowercase hex digits, joined by `:`, then
upper-cased.

### `get_ipv4_addr(bytes_addr)`
Formats a 4-byte address as dotted-decimal (`192.168.1.1`):

```python
return '.'.join(map(str, bytes_addr))
```

### `ethernet_frame(data)`
Parses the first 14 bytes of a captured frame.

```python
dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
```

| Field | Bytes | Format | Meaning |
|---|---|---|---|
| Destination MAC | 0–5 | `6s` | Receiver NIC |
| Source MAC | 6–11 | `6s` | Sender NIC |
| EtherType | 12–13 | `H` (big-endian) | Upper-layer protocol (`0x0800` = IPv4) |

Returns `(dest_mac, src_mac, eth_proto, data[14:])`.

### `ipv4_packet(data)`
Parses the 20-byte minimum IPv4 header.

```python
version_header_length = data[0]
version     = version_header_length >> 4
header_len  = (version_header_length & 0x0F) * 4
ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
```

- **Version** is the high nibble of byte 0.
- **Header Length (IHL)** is the low nibble × 4 (32-bit words → bytes).
- **Protocol** is the IP protocol number (`1` = ICMP, `6` = TCP).
- Returns the IP payload starting at `data[header_len:]` for further decoding.

### `icmp_packet(data)`
```python
icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
```
Returns type, code, checksum and the remaining bytes (ICMP payload).

### `tcp_segment(data)`
```python
src_port, dst_port, seq, ack, offset_flags = struct.unpack('! H H L L H', data[:14])
offset = (offset_flags >> 12) * 4
flags  = offset_flags & 0x3F
```
- The **Data Offset** (top 4 bits) × 4 gives the TCP header length in bytes.
- The **low 6 bits** are the control flags `URG, ACK, PSH, RST, SYN, FIN`.
- Returns the TCP payload starting at `data[offset:]`.

---

## 4. Packet Structure Reference

### Ethernet II frame
```
| Dest MAC (6) | Src MAC (6) | EtherType (2) | Payload ... |
```

### IPv4 header (minimum)
```
| Ver/IHL (1) | TOS (1) | Total Len (2) | ID (2) | Flags/Frag (2) |
| TTL (1) | Protocol (1) | Checksum (2) | Src IP (4) | Dst IP (4) | ...
```

### ICMP
```
| Type (1) | Code (1) | Checksum (2) | (Type-specific data) |
```
Common types: `0` Echo Reply, `8` Echo Request, `3` Destination Unreachable.

### TCP
```
| Src Port (2) | Dst Port (2) | Sequence (4) | Acknowledgment (4) |
| Data Offset / Reserved / Flags (2) | Window (2) | ... | Payload |
```
Control flags: **URG, ACK, PSH, RST, SYN, FIN**.

---

## 5. Running and Testing

1. **Syntax check** (safe, no network needed):
   ```bash
   python3 -m py_compile src/sniffer.py
   ```
2. **Offline parser tests** (safe, no socket, no root — runs on any OS):
   ```bash
   python3 tests/test_offline_parsers.py
   ```
   The suite (`unittest`, stdlib only) covers MAC formatting, Ethernet,
   IPv4, ICMP and TCP parsing with synthetic frames built via `struct`,
   including truncated/invalid inputs. **Current status: 16/16 tests pass.**
3. **Run** (requires Linux + root):
   ```bash
   sudo python3 sniffer.py
   ```
4. **Generate traffic**:
   ```bash
   ping 8.8.8.8
   ```

---

## 6. Robustness & Error Handling

Every parser validates the minimum header length before unpacking and raises a
clear `ValueError` for truncated data; the capture loop catches these errors
per-packet, prints a warning and keeps capturing.

| Parser | Minimum bytes | Protection |
|---|---|---|
| `ethernet_frame()` | 14 | Rejects frames shorter than the Ethernet header. |
| `ipv4_packet()` | 20 | Rejects truncated IP headers and IHL values that decode to < 20 bytes. |
| `icmp_packet()` | 4 | Rejects truncated ICMP headers. |
| `tcp_segment()` | 14 | Rejects truncated TCP headers; a bogus Data Offset (< 20) is clamped to 20 so header bytes never leak into the payload. |

Byte order note: all multi-byte fields are unpacked with `!` (network /
big-endian) — EtherType, TTL/protocol positions, IP addresses, ICMP checksum,
TCP ports, sequence/acknowledgment numbers and the flags word. The socket
protocol `socket.ntohs(3)` is the standard idiom for `ETH_P_ALL` on an
`AF_PACKET` socket.


---

## 7. Environment & Privileges

- **OS:** Linux (developed/tested on Kali Linux under VirtualBox).
- **Privileges:** `sudo` / root is mandatory — raw `AF_PACKET` sockets require
  the `CAP_NET_RAW` capability.
- **Dependencies:** Python 3 standard library only (`socket`, `struct`, and
  `unittest` for the offline tests).

---

## 8. Extending the Project

Possible improvements (not part of the original lab):
- Decode **UDP** segments.
- Add **BPF filters** (`setsockopt` with `SO_ATTACH_FILTER`) to capture only
  specific traffic.
- Write captured packets to a **`.pcap`** file for analysis in Wireshark.
- Pretty-print the TCP payload as ASCII/hex.
