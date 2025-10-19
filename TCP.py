"""
TCP.py      COSC 60      Oct 19th, 2025

Author: Ahmed Al Sunbati
Description: Represents the Transmission Control Protocol (TCP) layer (Layer 4).
             Provides functionality for building and parsing TCP headers, computing
             checksums (using the IP pseudo-header), and encapsulating higher-layer payloads.
"""

import struct
import socket
from Packet import Packet


class TCP(Packet):
    def __init__(self, src_port=None, dst_port=None, seq=0, ack_seq=0,
                 data_offset=5, flags=0x02, window=8192, checksum=0, urg_ptr=0,
                 data=b'', raw_bytes=None, ip_src=None, ip_dst=None, payload=None):
        """
        Description: Initializes a TCP packet. Can either construct from provided parameters
                     (for sending) or parse from raw bytes (for received data).

        @param src_port: Source TCP port number.
        @param dst_port: Destination TCP port number.
        @param seq: Sequence number.
        @param ack_seq: Acknowledgment number.
        @param data_offset: Header length in 32-bit words (default 5 → 20 bytes).
        @param flags: Control flags (SYN=0x02, ACK=0x10, FIN=0x01).
        @param window: Window size.
        @param checksum: Header checksum (computed automatically if not provided).
        @param urg_ptr: Urgent pointer.
        @param data: (bytes) Payload data.
        @param raw_bytes: Raw TCP segment for parsing.
        @param ip_src: Source IPv4 address (for checksum computation).
        @param ip_dst: Destination IPv4 address (for checksum computation).
        @param payload: (Packet or None) Next encapsulated layer.
        @returns: None
        """
        super().__init__(payload=payload)

        if raw_bytes:
            # Parse from received bytes
            self.src_port, self.dst_port, self.seq, self.ack_seq, offset_reserved_flags, \
                self.window, self.checksum, self.urg_ptr = struct.unpack('!HHLLHHHH', raw_bytes[:20])
            self.data_offset = (offset_reserved_flags >> 12)
            self.flags = offset_reserved_flags & 0xFFF
            self.data = raw_bytes[self.data_offset * 4:]
        else:
            # Construct a new TCP segment
            self.src_port = src_port or 12345
            self.dst_port = dst_port or 80
            self.seq = seq
            self.ack_seq = ack_seq
            self.data_offset = data_offset
            self.flags = flags
            self.window = window
            self.checksum = checksum
            self.urg_ptr = urg_ptr
            self.data = data
            self.ip_src = ip_src
            self.ip_dst = ip_dst

            # Compute checksum if IP info is provided
            self.checksum = self.compute_checksum() if ip_src and ip_dst else 0

    def compute_checksum(self):
        """
        Description: Computes the TCP checksum, including the pseudo-header
                     (which uses the source and destination IPs from the IP layer).

        @returns: The computed checksum value.
        """
        pseudo_header = struct.pack(
            '!4s4sBBH',
            socket.inet_aton(self.ip_src),
            socket.inet_aton(self.ip_dst),
            0,
            socket.IPPROTO_TCP,
            self.data_offset * 4 + len(self.data)
        )

        tcp_header = struct.pack(
            '!HHLLHHHH',
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            (self.data_offset << 12) + self.flags,
            self.window,
            0,  # checksum set to zero for calculation
            self.urg_ptr
        )

        segment = pseudo_header + tcp_header + self.data
        if len(segment) % 2 == 1:
            segment += b'\x00'

        total = sum(struct.unpack('!%dH' % (len(segment) // 2), segment))
        total = (total >> 16) + (total & 0xFFFF)
        total += total >> 16
        return ~total & 0xFFFF

    def build(self):
        """
        Description: Constructs the byte representation of the TCP segment, including
                     header and data, followed by recursively built payload (if any).

        @returns: (bytes) Complete TCP segment bytes.
        """
        header_bytes = struct.pack(
            '!HHLLHHHH',
            self.src_port,
            self.dst_port,
            self.seq,
            self.ack_seq,
            (self.data_offset << 12) + self.flags,
            self.window,
            self.checksum,
            self.urg_ptr
        )

        packet_bytes = header_bytes + self.data
        if self.payload:
            packet_bytes += self.payload.build()
        return packet_bytes

    def show(self, indent=0):
        """
        Description: Displays a human-readable representation of the TCP header and its payload.

        @param indent: (int) Indentation level for nested layers.
        @returns: None
        """
        print(" " * indent + f"### TCP (Layer 4) ###")
        print(" " * (indent + 1) + f"src_port: {self.src_port}")
        print(" " * (indent + 1) + f"dst_port: {self.dst_port}")
        print(" " * (indent + 1) + f"seq: {self.seq}")
        print(" " * (indent + 1) + f"ack_seq: {self.ack_seq}")
        print(" " * (indent + 1) + f"flags: 0x{self.flags:03x}")
        print(" " * (indent + 1) + f"window: {self.window}")
        print(" " * (indent + 1) + f"checksum: 0x{self.checksum:04x}")
        print(" " * (indent + 1) + f"urg_ptr: {self.urg_ptr}")
        if self.data:
            print(" " * (indent + 1) + f"data: {self.data}")
        if self.payload:
            self.payload.show(indent + 1)
