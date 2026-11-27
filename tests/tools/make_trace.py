#!/usr/bin/env python3
"""Generate small UDP pcaps carrying malformed FailDemo messages.

The parser in tests/analyzer/faildemo.spicy dispatches on the first byte:

  kind 1 -> truncated payload, classified as TRUNCATED
  kind 2 -> wrong magic literal, classified as FORMAT
  kind 3 -> &requires constraint failure, classified as CONSTRAINT

Only the Python standard library is used so the tool runs in any minimal
CI container. Each malformed datagram is sent over a unique 4-tuple so that
replaying several samples in one pcap cannot cross-contaminate connections.
"""

import argparse
import socket
import struct


DPORT = 43107

# kind, hex payload, expected category, human-readable description.
CASES = (
    (1, "01" "50524f4245" "05" "4141", "TRUNCATED",
     "length says 5 bytes but only 2 follow"),
    (2, "02" "58524f4245", "FORMAT",
     'magic literal "PROBE" expected but input starts with "XROBE"'),
    (3, "03" "09" "414243", "CONSTRAINT",
     "length 9 violates &requires (must be <= 3)"),
)


def ipv4_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_packet(src_ip: str, dst_ip: str, sport: int, payload: bytes) -> bytes:
    eth = (
        b"\x02\x00\x00\x00\x00\x02"
        + b"\x02\x00\x00\x00\x00\x01"
        + struct.pack("!H", 0x0800)
    )

    udp = struct.pack("!HHHH", sport, DPORT, 8 + len(payload), 0)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload),
        0x1234, 0, 64, 17, 0, src, dst,
    )
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    return eth + ip + udp + payload


def write_pcap(path: str, packets):
    with open(path, "wb") as handle:
        # Global header: magic, version 2.4, this zone, snaplen, LINKTYPE_ETHERNET.
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            handle.write(struct.pack("<IIII", index, 0, len(packet), len(packet)))
            handle.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", help="path of the pcap file to write")
    parser.add_argument(
        "--kind",
        type=int,
        choices=sorted(case[0] for case in CASES),
        help="write only one malformed datagram of the given kind",
    )
    args = parser.parse_args()

    packets = []
    for index, (kind, payload_hex, category, description) in enumerate(CASES):
        if args.kind is not None and kind != args.kind:
            continue
        payload = bytes.fromhex(payload_hex)
        sport = 53000 + index
        packets.append(
            udp_packet("10.0.0.1", "10.0.0.2", sport, payload)
        )
        print(f"kind={kind} category={category} ({description})")

    write_pcap(args.output, packets)
    print(f"wrote {len(packets)} datagram(s) to {args.output}")


if __name__ == "__main__":
    main()
