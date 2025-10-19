"""
ICMP.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the Internet Control Message Protocol (ICMP) layer (Layer 3).
             Supports building ICMP headers, computing checksums, and parsing from raw bytes.
"""

import struct
from Packet import Packet


class ICMP(Packet):
    def __init__(self, type=8, code=0, checksum=0, identifier=0, seq=0,
                 data=b'', raw_bytes=None, payload=None):
        """
        Description: Initializes an ICMP packet. Can construct from parameters (for sending)
                     or parse from raw bytes (for received data).

        @param type: ICMP type (8 = echo request, 0 = echo reply, etc.).
        @param code: ICMP code (usually 0).
        @param checksum: Checksum (computed automatically if 0).
        @param identifier: Identifier field (used for echo requests/replies).
        @param seq: Sequence number (used for echo requests/replies).
        @param data: Optional payload data.
        @param raw_bytes: If provided, parse these bytes.
        @param payload: Next encapsulated layer (usually None for ICMP).
        """
        super().__init__(payload)

        if raw_bytes:
            self._parse(raw_bytes)
        else:
            self.type = type
            self.code = code
            self.checksum = checksum
            self.identifier = identifier
            self.seq = seq
            self.data = data

            # Compute checksum if not provided
            if self.checksum == 0:
                self.checksum = self.compute_checksum()

    def _parse(self, raw_bytes):
        """
        Description: Parses ICMP header and data from raw bytes.
        """
        self.type, self.code, self.checksum, self.identifier, self.seq = struct.unpack(
            "!BBHHH", raw_bytes[:8]
        )
        self.data = raw_bytes[8:]
        self.payload = None  # ICMP usually has no higher layer

    def compute_checksum(self):
        """
        Description: Computes the ICMP checksum using one's complement sum.
        """
        header = struct.pack(
            "!BBHHH",
            self.type,
            self.code,
            0,  # checksum zeroed for computation
            self.identifier,
            self.seq
        )
        segment = header + self.data
        if len(segment) % 2 == 1:
            segment += b'\x00'
        total = sum(struct.unpack('!%dH' % (len(segment) // 2), segment))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    def build(self):
        """
        Description: Builds ICMP header + data into bytes.
        """
        header_bytes = struct.pack(
            "!BBHHH",
            self.type,
            self.code,
            self.checksum,
            self.identifier,
            self.seq
        )
        packet_bytes = header_bytes + self.data
        if self.payload:
            packet_bytes += self.payload.build()
        return packet_bytes

    def show(self, indent=0):
        """
        Description: Prints a human-readable representation of ICMP packet.
        """
        print(" " * indent + f"### ICMP (Layer 3) ###")
        print(" " * (indent + 1) + f"type: {self.type}")
        print(" " * (indent + 1) + f"code: {self.code}")
        print(" " * (indent + 1) + f"checksum: 0x{self.checksum:04x}")
        print(" " * (indent + 1) + f"identifier: {self.identifier}")
        print(" " * (indent + 1) + f"seq: {self.seq}")
        if self.data:
            print(" " * (indent + 1) + f"data: {self.data}")
        if self.payload:
            self.payload.show(indent + 1)
