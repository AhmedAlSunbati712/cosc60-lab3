import struct
from Packet import Packet

class UDP(Packet):
    """
    UDP (User Datagram Protocol) Layer - Layer 4

    Handles construction and parsing of UDP headers.
    Supports both parameter-based initialization and raw-byte parsing.
    """

    def __init__(self, raw_bytes=None, src_port=None, dst_port=None,
                 payload=None, src_ip=None, dst_ip=None):
        """
        Description: Initialize a UDP layer.

        @param raw_bytes: (bytes) Raw UDP header and data to parse (optional)
        @param src_port: (int) Source port number (default 12345)
        @param dst_port: (int) Destination port number (default 53)
        @param payload: (Packet or None) Encapsulated higher-layer data
        @param src_ip: (str) Source IP (for checksum computation, optional)
        @param dst_ip: (str) Destination IP (for checksum computation, optional)
        """
        super().__init__(payload)

        if raw_bytes:
            # Parse UDP header from raw bytes
            self.src_port, self.dst_port, self.length, self.checksum = struct.unpack('!HHHH', raw_bytes[:8])
            self.data = raw_bytes[8:]
        else:
            self.src_port = src_port if src_port is not None else 12345
            self.dst_port = dst_port if dst_port is not None else 53
            self.data = b''  # Only used if payload is None
            self.src_ip = src_ip
            self.dst_ip = dst_ip

            payload_bytes = self.payload.build() if self.payload else self.data
            self.length = 8 + len(payload_bytes)
            self.checksum = self._compute_checksum(payload_bytes) if (src_ip and dst_ip) else 0

    def _compute_checksum(self, payload_bytes):
        """
        Description: Compute the UDP checksum including the pseudo-header.

        @param payload_bytes:
            The data portion of the UDP segment, usually generated from the payload’s build() method.
            This may represent the bytes of a higher-layer protocol (e.g., DNS) or raw application data.

        @returns:
            The 16-bit UDP checksum value, computed according to the Internet standard.
            If the computed checksum equals 0, the value transmitted will be 0xFFFF.
        """
        pseudo_header = b''

        # Convert IP addresses to bytes
        src_ip_bytes = struct.pack('!4B', *[int(x) for x in self.src_ip.split('.')])
        dst_ip_bytes = struct.pack('!4B', *[int(x) for x in self.dst_ip.split('.')])
        protocol = 17  # UDP
        udp_length = self.length

        # Build pseudo-header: src_ip + dst_ip + zero + protocol + UDP length
        pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, protocol, udp_length)

        # UDP header without checksum (checksum field = 0 for calculation)
        header = struct.pack('!HHHH', self.src_port, self.dst_port, self.length, 0)

        checksum_data = pseudo_header + header + payload_bytes

        # If odd length, pad with zero byte
        if len(checksum_data) % 2 == 1:
            checksum_data += b'\x00'

        checksum = 0
        for i in range(0, len(checksum_data), 2):
            word = (checksum_data[i] << 8) + checksum_data[i + 1]
            checksum += word
            checksum = (checksum & 0xFFFF) + (checksum >> 16)  # Carry around

        checksum = ~checksum & 0xFFFF
        return checksum

    def build(self):
        """
        Description: Build the byte representation of the UDP packet.
        """
        payload_bytes = self.payload.build() if self.payload else self.data
        header = struct.pack('!HHHH', self.src_port, self.dst_port, self.length, self.checksum)
        return header + payload_bytes

    def show(self, indent=0):
        """
        Description: Display UDP header info (overrides Packet.show for custom formatting).
        """
        print(" " * indent + f"### UDP ###")
        print(" " * (indent + 1) + f"Source Port: {self.src_port}")
        print(" " * (indent + 1) + f"Destination Port: {self.dst_port}")
        print(" " * (indent + 1) + f"Length: {self.length}")
        print(" " * (indent + 1) + f"Checksum: {hex(self.checksum)}")
        if self.payload:
            self.payload.show(indent + 1)
