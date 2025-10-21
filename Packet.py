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
        packet_bytes = self.to_bytes() if hasattr(self, 'to_bytes') else b''
        if self.payload: 
            packet_bytes += self.payload.to_bytes() if hasattr(self.payload, 'to_bytes') else (self.payload if isinstance(self.payload, bytes) else b'')# Build the bytes of the payload layer recursively
        return packet_bytes
    
    def __truediv__(self, other):
        """
        Description: Overloads the division (/) operator to allow stacking of protocol layers.

        @param other: The higher-layer packet to encapsulate as this packet’s payload.
        @returns: The current packet instance (to allow chaining).
        """
        #if paylaod is none or raw bytes replace with nxt layer
        if self.payload is None or isinstance(self.payload, bytes):
            self.payload = other
        else:
            self.payload / other
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
            if isinstance(self.payload, Packet):
                self.payload.show(indent + 1)
            elif isinstance(self.payload, bytes):
                print(" " * (indent + 1) + f"payload (raw bytes): {self.payload.hex()}")
            else:
                print(" " * (indent + 1) + f"payload (unknown type): {self.payload}")
