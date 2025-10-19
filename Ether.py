"""
Ether.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the Ethernet (Layer 2) packet structure. Supports both construction
             from header parameters and parsing from raw bytes. Provides methods to build
             byte sequences and recursively display encapsulated layers.
"""

import struct
from Packet import Packet
from IP import IP


class Ether(Packet):
    def __init__(self, src_mac=None, dst_mac=None, eth_type=0x0800, payload=None, raw_bytes=None):
        """
        Description: Initializes an Ethernet frame. Can be built from header fields or parsed from raw bytes.

        @param src_mac: Source MAC address, e.g. "aa:bb:cc:dd:ee:ff"
        @param dst_mac: Destination MAC address, e.g. "ff:ff:ff:ff:ff:ff"
        @param eth_type: EtherType field (default 0x0800 for IPv4)
        @param payload: Encapsulated payload (IP layer)
        @param raw_bytes: Optional raw bytes for parsing
        @returns: None
        """
        super().__init__(payload)
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.eth_type = eth_type

        if raw_bytes is not None:
            self._from_bytes(raw_bytes)

    def _from_bytes(self, raw_bytes):
        """
        Description: Parses Ethernet header fields from raw bytes and
                     creates an appropriate payload layer (e.g., IP).

        @param raw_bytes: Raw packet bytes.
        @returns: None
        """
        header = raw_bytes[:14]
        dst, src, eth_type = struct.unpack("!6s6sH", header)
        self.dst_mac = self._format_mac(dst)
        self.src_mac = self._format_mac(src)
        self.eth_type = eth_type

        payload_bytes = raw_bytes[14:]
        # If IPv4, automatically build an IP layer
        if self.eth_type == 0x0800:
            self.payload = IP(raw_bytes=payload_bytes)
        else:
            self.payload = payload_bytes

    def _format_mac(self, mac_bytes):
        """Converts bytes → colon-separated MAC string."""
        return ":".join(f"{b:02x}" for b in mac_bytes)

    def _parse_mac(self, mac_str):
        """Converts colon-separated MAC string → bytes."""
        return bytes(int(x, 16) for x in mac_str.split(":"))
    
    def build(self):
        """
        Description: Builds the byte representation of the Ethernet frame
                     and recursively builds its payload.

        @returns: Complete Ethernet frame.
        """
        dst_bytes = self._parse_mac(self.dst_mac)
        src_bytes = self._parse_mac(self.src_mac)

        header = struct.pack("!6s6sH", dst_bytes, src_bytes, self.eth_type)

        payload_bytes = b""
        if self.payload:
            payload_bytes = self.payload.build()

        return header + payload_bytes
    
    def show(self, indent=0):
        print(" " * indent + f"### Ether ###")
        print(" " * (indent + 1) + f"src_mac: {self.src_mac}")
        print(" " * (indent + 1) + f"dst_mac: {self.dst_mac}")
        print(" " * (indent + 1) + f"eth_type: 0x{self.eth_type:04x}")
        if self.payload:
            self.payload.show(indent + 1)

