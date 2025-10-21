"""
ICMP.py      COSC 60      Oct 19th, 2025

Author: Dejanae Green
Description: Implements the Internet Control Message Protocol (ICMP) layer (Layer 3).
             Supports building ICMP headers, computing checksums, and parsing from raw bytes.
"""

import struct
from Packet import Packet
import random


class ICMP(Packet):
    def __init__(self, icmp_type= 8, code=0, payload=b'', ID=0, seq=0, raw= None):
        """
        Description: Initializes an ICMP packet. Can construct from parameters (for sending)
                     or parse from raw bytes (for received data).

        @param icmp_type: ICMP type (8 = echo request, 0 = echo reply, etc.).
        @param code: ICMP code (usually 0).
        @param ID: Identifier field (used for echo requests/replies).
        @param seq: Sequence number (used for echo requests/replies).
        @param raw: If provided, parse these bytes.
        @param payload: Next encapsulated layer (usually None for ICMP).
        """
        if raw:
            header = raw[:8]
            #1 byte for type and code each 2 bytes for chcksum, header and sequence number each
    
            self.icmp_type, self.code, self.checksum, self.ID, self.seq = struct.unpack('!BBHHH', header)
            payload_data = raw[8:] if len(raw) > 8 else b''
            self.payload = payload_data
        #default if no packet recieved
        else:
            #ensure payload is bytes
            if payload is None:
                payload = b''
            super().__init__(payload)
            #place holder will calculae in to_bytes
            self.checksum = 0
            self.icmp_type = int(icmp_type)
            self.ID = int(ID) if ID is not None else random.randint(0, 65535)
            self.seq = int(seq)
            self.code = int(code)
#cite: https://stackoverflow.com/questions/20247551/icmp-echo-checksum
    def checksum_ICMP(self, data):
        """
        Description: Computes the ICMP checksum using one's complement sum.
        """
        #similiar to the IP check sum calculations
        #if odd number add an extra bit
        if len(data) % 2:
            data += b'\x00'
        sumd = sum(struct.unpack('!%dH' % (len(data)//2), data))
        #carry operations. handles overflow from the 16 bits
        sumd = (sumd >> 16) + (sumd & 0xFFFF)
        sumd += sumd >> 16
        #complment of the 16-bit sum mask to 16 bits
        return (~sumd) & 0xFFFF
def to_bytes(self):
        """
        Description: Parses ICMP header and data from raw bytes.
        """
        #make sure is bytes
        payload_bytes = self.payload if isinstance(self.payload, bytes) else b''
        #placeholder checksum will calcualte later
        #header with zero checksum placeholder
        header_0CS = struct.pack('!BBHHH', self.icmp_type, self.code, 0, self.ID, self.seq)
        # add payload on top of header
        data = header_0CS + payload_bytes
        #calcualte checksum then add that checksum to the header
        self.checksum = self.checksum_ICMP(data)
        header = struct.pack('!BBHHH', self.icmp_type, self.code, self.checksum, self.ID, self.seq)
        return header + payload_bytes
   

   