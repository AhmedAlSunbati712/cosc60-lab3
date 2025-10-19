"""
Packet.py      COSC 60      Oct 16th, 2025

Author: Ahmed Al Sunbati
Description: Base class for all network protocol layers. Provides common functionality for
             building packet bytes and recursively displaying the structure of encapsulated layers.
             Each subclass should override the build() method to generate its specific header bytes.
"""
class Packet:
    def __init__(self, payload=None):
        """
        Description: Initializes a Packet instance. Each packet can contain another packet
                     as its payload, forming a recursive structure (Ether -> IP -> TCP -> DNS).

        @param payload: (Packet or None) The next protocol layer encapsulated by this one.
        @returns: None
        """
        self.payload = payload
    def build(self):
        """
        Description: Recursively constructs the byte representation of this packet and all encapsulated layers.
                     Each subclass should override this method to include its own header fields in 'header_bytes'.
                     The payload’s build() method is then called to append its bytes.

        @returns: (bytes) The full byte sequence of the current layer and all nested payloads.
        """
        packet_bytes = b''
        header_bytes = b'' # Override in subclasses with the bytes of the headers
    
        packet_bytes += header_bytes
        if self.payload:
            packet_bytes += self.payload.build() # Build the bytes of the payload layer recursively
        return packet_bytes
    def __truediv__(self, other):
        """
        Description: Overloads the division (/) operator to allow stacking of protocol layers.

        @param other: The higher-layer packet to encapsulate as this packet’s payload.
        @returns: The current packet instance (to allow chaining).
        """
        self.payload = other

        # Handle auto IP propagation for transport layers
        if hasattr(self, 'src_ip') and hasattr(self, 'dst_ip'):
            # self is likely an IP layer
            if hasattr(other, 'src_port') and hasattr(other, 'dst_port'):
                # other is likely TCP or UDP layer
                if not hasattr(other, 'src_ip'):
                    other.src_ip = self.src_ip
                if not hasattr(other, 'dst_ip'):
                    other.dst_ip = self.dst_ip

        return self
    def show(self, indent=0):
        """
        Description: Prints a hierarchical, human-readable view of the packet’s header fields and payload layers.
                     Each level of indentation represents a deeper encapsulation.

        @param indent: (int) The indentation level used for nested printing.
        @returns: None
        """
        print(" " * indent + f"### {self.__class__.__name__} ###")
        for key, value in vars(self).items():
            if key != "payload":
                print(" " * (indent + 1) + f"{key}: {value}")
        if self.payload:
            self.payload.show(indent + 1)
