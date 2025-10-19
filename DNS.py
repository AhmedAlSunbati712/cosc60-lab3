"""
DNS.py      COSC 60      Oct 19th, 2025

Author: Ahmed Al Sunbati
Description: Represents the Domain Name System (DNS) application layer (Layer 7).
             Supports building DNS queries and parsing responses. Designed to be encapsulated
             by UDP at Layer 4 and to serve as the final payload (payload=None).
"""

import struct
from Packet import Packet


class DNS(Packet):
    def __init__(self, transaction_id=None, flags=None,
                 qdcount=1, ancount=0, nscount=0, arcount=0,
                 qname=None, qtype=1, qclass=1, raw_bytes=None, payload=None):
        """
        Description: Initializes a DNS packet. Can either construct a new DNS query
                     or parse an existing DNS message from raw bytes.

        @param transaction_id: Unique ID for matching DNS requests and responses.
        @param flags: 16-bit flags field (0x0100 for standard query).
        @param qdcount: Number of questions in the query section.
        @param ancount: Number of resource records in the answer section.
        @param nscount: Number of name server resource records.
        @param arcount: Number of additional resource records.
        @param qname: Domain name being queried.
        @param qtype:  Type of query (1 = A, 28 = AAAA, etc.).
        @param qclass:  Class of query (1 = IN).
        @param raw_bytes: Raw DNS message to parse.
        @param payload: Next layer (should be None for DNS).
        @returns: None
        """
        super().__init__(payload=payload)

        if raw_bytes:
            # Parse header
            (self.transaction_id, self.flags, self.qdcount, self.ancount,
             self.nscount, self.arcount) = struct.unpack("!HHHHHH", raw_bytes[:12])

            # Parse question section (simplified for single query)
            offset = 12
            self.qname, offset = self._parse_qname(raw_bytes, offset)
            self.qtype, self.qclass = struct.unpack("!HH", raw_bytes[offset:offset + 4])
        else:
            # Build a new query
            self.transaction_id = transaction_id or 0xAAAA
            self.flags = flags or 0x0100  # Standard query
            self.qdcount = qdcount
            self.ancount = ancount
            self.nscount = nscount
            self.arcount = arcount
            self.qname = qname or "example.com"
            self.qtype = qtype
            self.qclass = qclass

    def _encode_qname(self, name):
        """
        Description: Converts a human-readable domain name into DNS label format.
                     "example.com" → b'\x07example\x03com\x00'

        @param name: Domain name to encode.
        @returns: Encoded domain name in DNS label format.
        """
        parts = name.split(".")
        encoded = b''.join(struct.pack("B", len(part)) + part.encode() for part in parts)
        return encoded + b'\x00'

    def _parse_qname(self, data, offset):
        """
        Description: Parses a QNAME field from raw DNS bytes, following label encoding.

        @param data: Raw DNS message.
        @param offset: Starting position of QNAME.
        @returns: Parsed domain name and new offset position.
        """
        labels = []
        while True:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length].decode())
            offset += length
        return ".".join(labels), offset

    def build(self):
        """
        Description: Constructs the byte representation of the DNS query message.
                     This includes the header and the question section.

        @returns: Fully constructed DNS message bytes.
        """
        header = struct.pack(
            "!HHHHHH",
            self.transaction_id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount
        )

        question = self._encode_qname(self.qname)
        question += struct.pack("!HH", self.qtype, self.qclass)

        packet_bytes = header + question
        if self.payload:
            packet_bytes += self.payload.build()
        return packet_bytes

    def show(self, indent=0):
        """
        Description: Prints a readable representation of the DNS header and question section.

        @param indent: Indentation level for nested layers.
        @returns: None
        """
        print(" " * indent + "### DNS (Layer 7) ###")
        print(" " * (indent + 1) + f"transaction_id: 0x{self.transaction_id:04x}")
        print(" " * (indent + 1) + f"flags: 0x{self.flags:04x}")
        print(" " * (indent + 1) + f"qdcount: {self.qdcount}")
        print(" " * (indent + 1) + f"ancount: {self.ancount}")
        print(" " * (indent + 1) + f"nscount: {self.nscount}")
        print(" " * (indent + 1) + f"arcount: {self.arcount}")
        print(" " * (indent + 1) + f"qname: {self.qname}")
        print(" " * (indent + 1) + f"qtype: {self.qtype}")
        print(" " * (indent + 1) + f"qclass: {self.qclass}")
        if self.payload:
            self.payload.show(indent + 1)
