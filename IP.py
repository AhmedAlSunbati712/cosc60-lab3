"""
IP.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the IPv4 protocol layer (Layer 3).
             Supports building IPv4 headers, checksum calculation,
             and parsing from raw bytes.
"""

import struct
import socket
from Packet import Packet


class IP(Packet):
    def __init__(self, src_ip="0.0.0.0", dst_ip="0.0.0.0", ttl=64, proto=0,
                 identification=0, flags_fragment=0, raw_bytes=None, payload=None):
        """
        Description: Initializes an IPv4 packet. Can construct from provided
                     fields (for sending) or parse from raw bytes (for receiving).

        @param src_ip: Source IPv4 address.
        @param dst_ip: Destination IPv4 address.
        @param ttl: Time to Live.
        @param proto: Protocol number (e.g., 6 for TCP, 17 for UDP).
        @param identification: Identification field.
        @param flags_fragment: Flags + Fragment offset field.
        @param raw_bytes: If provided, parse these bytes.
        @param payload: Next layer encapsulated.
        @returns: None
        """
        super().__init__(payload)

        if raw_bytes:
            self._parse(raw_bytes)
        else:
            self.version = 4
            self.ihl = 5  # header length (in 32-bit words)
            self.tos = 0
            self.total_length = 0  # will fill in later
            self.identification = identification
            self.flags_fragment = flags_fragment
            self.ttl = ttl
            self.proto = proto
            self.checksum = 0
            self.src_ip = src_ip
            self.dst_ip = dst_ip

    def _parse(self, raw_bytes):
        """
        Description: Internal helper to parse an IPv4 header from raw bytes.
        """
        (version_ihl, self.tos, self.total_length, self.identification,
         self.flags_fragment, self.ttl, self.proto, self.checksum,
         src_ip, dst_ip) = struct.unpack("!BBHHHBBH4s4s", raw_bytes[:20])

        self.version = version_ihl >> 4
        self.ihl = version_ihl & 0xF
        self.src_ip = socket.inet_ntoa(src_ip)
        self.dst_ip = socket.inet_ntoa(dst_ip)
        self.payload = raw_bytes[self.ihl * 4:]

    def compute_checksum(self, header):
        """
        Description: Computes IPv4 header checksum.

        @param header: IPv4 header with checksum set to 0.
        @returns: 16-bit checksum.
        """
        if len(header) % 2:
            header += b'\x00'
        total = sum(struct.unpack('!%dH' % (len(header) // 2), header))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    def build(self):
        """
        Description: Builds IPv4 header and recursively appends payload bytes.

        @returns: Complete IPv4 packet (header + payload).
        """
        payload_bytes = self.payload.build() if self.payload else b''
        self.total_length = 20 + len(payload_bytes)

        version_ihl = (self.version << 4) + self.ihl
        header_wo_checksum = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_fragment,
            self.ttl,
            self.proto,
            0,
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.dst_ip)
        )

        self.checksum = self.compute_checksum(header_wo_checksum)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            self.total_length,
            self.identification,
            self.flags_fragment,
            self.ttl,
            self.proto,
            self.checksum,
            socket.inet_aton(self.src_ip),
            socket.inet_aton(self.dst_ip)
        )

        return header + payload_bytes

    def show(self, indent=0):
        """
        Description: Displays a human-readable view of IPv4 header fields.

        @param indent: Indentation level for nested layers.
        @returns: None
        """
        print(" " * indent + f"### IP (Layer 3) ###")
        print(" " * (indent + 1) + f"src_ip: {self.src_ip}")
        print(" " * (indent + 1) + f"dst_ip: {self.dst_ip}")
        print(" " * (indent + 1) + f"ttl: {self.ttl}")
        print(" " * (indent + 1) + f"proto: {self.proto}")
        print(" " * (indent + 1) + f"checksum: 0x{self.checksum:04x}")
        if self.payload:
            self.payload.show(indent + 1)
